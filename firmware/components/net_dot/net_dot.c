/*
 * net_dot — upstream DoT (RFC 7858) (HW, spec 007). Ver net_dot.h.
 *
 * Diseño: la ruta rápida (hilo tcpip) registra dot_submit como forward de
 * net_dns; dot_submit copia la consulta a una cola acotada y vuelve al instante
 * (nunca bloquea, FR-006). Una tarea dedicada saca de la cola y hace el TLS
 * bloqueante: mantiene una conexión esp-tls persistente a upstream[i]:853
 * (conectando por IP para NO filtrar el resolvedor a un DNS en claro, y
 * validando el certificado contra el hostname con el bundle de CAs). Envía
 * [len][consulta], lee [len][respuesta], la valida (dot_frame), la manda al
 * cliente y la cachea. Error ⇒ failover al siguiente resolvedor cifrado; si
 * ninguno responde ⇒ SERVFAIL local (fail-closed, FR-003): jamás UDP en claro.
 */
#include "net_dot.h"

#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/ip_addr.h"
#include "lwip/sockets.h"

#include "config_nvs.h"
#include "dns_wire.h"
#include "dot_frame.h"
#include "esphole_types.h"
#include "net_dns.h"

static const char *TAG = "net_dot";

#define DOT_PORT             853
#define DOT_QUEUE_DEPTH      16     /* cola acotada (FR-007) */
#define DOT_TASK_STACK       8192   /* stack de la tarea (TLS) */
#define DOT_CONNECT_TMO_MS   2500   /* handshake TLS (failover snappier si un upstream cae) */
#define DOT_IO_TMO_MS        2500   /* lectura/escritura de un mensaje */
#define DOT_BACKOFF_MS       2000   /* espera tras agotar todos los resolvedores */

/* Una entrada de la cola: descriptor + copia del datagrama (q.raw es transitorio). */
typedef struct {
    dns_query_t q;
    uint8_t raw[NET_DNS_MAX_QUERY];
} dot_item_t;

/* --- estado del módulo (lo escribe/lee solo la tarea DoT, salvo contadores) --- */
static QueueHandle_t s_queue;
static TaskHandle_t s_task;
static volatile bool s_running;
static volatile bool s_stop;
static SemaphoreHandle_t s_done; /* la tarea lo señala al salir (join fiable) */
static net_dns_forward_fn s_saved_forward; /* forward UDP a restaurar */

/* upstreams + SNI (instantánea al arrancar). */
static ip_addr16_t s_addr[CONFIG_UPSTREAMS_MAX];
static char s_sni[CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX];
static int s_count;
static int s_active = -1; /* upstream cifrado en uso */

/* conexión TLS persistente */
static esp_tls_t *s_tls;
static int s_conn_idx = -1;

/* cortacircuitos: mientras esp_timer_get_time() < esto, sabemos que todos los
 * resolvedores están caídos ⇒ fail-closed inmediato (sin re-intentar handshakes). */
static volatile int64_t s_alldown_until;

/* contadores/estado para la API (lecturas benignas de monitoreo) */
static volatile bool s_connected;
static volatile uint32_t s_served, s_servfail, s_dropped;
static char s_last_error[128];

/* scratch de encolado: solo lo usa dot_submit en el hilo tcpip (serie). */
static dot_item_t s_scratch;

/* --- helpers --- */

static void hacia_lwip(const ip_addr16_t *a, ip_addr_t *out)
{
    memset(out, 0, sizeof(*out));
    if (a->family == ESPHOLE_AF_V4) {
        IP_SET_TYPE(out, IPADDR_TYPE_V4);
        IP4_ADDR(ip_2_ip4(out), a->bytes[0], a->bytes[1], a->bytes[2], a->bytes[3]);
    } else {
        IP_SET_TYPE(out, IPADDR_TYPE_V6);
        ip6_addr_t *d = ip_2_ip6(out);
        for (int g = 0; g < 4; g++) {
            d->addr[g] = lwip_htonl(((uint32_t)a->bytes[g * 4] << 24) |
                                    ((uint32_t)a->bytes[g * 4 + 1] << 16) |
                                    ((uint32_t)a->bytes[g * 4 + 2] << 8) |
                                    a->bytes[g * 4 + 3]);
        }
        ip6_addr_clear_zone(d);
    }
}

/* Formatea el IP literal del upstream (sin DNS). false si no se pudo. */
static bool ip16_str(const ip_addr16_t *a, char *out, size_t cap)
{
    ip_addr_t ip;
    hacia_lwip(a, &ip);
    return ipaddr_ntoa_r(&ip, out, (int)cap) != NULL;
}

static void close_conn(void)
{
    if (s_tls != NULL) {
        esp_tls_conn_destroy(s_tls);
        s_tls = NULL;
    }
    s_conn_idx = -1;
    s_connected = false;
}

/* Conecta (si hace falta) al upstream idx por DoT. Reusa la conexión viva. */
static bool ensure_connected(int idx)
{
    if (s_tls != NULL && s_conn_idx == idx) {
        return true; /* conexión persistente reutilizable */
    }
    close_conn();

    char ip[48];
    if (!ip16_str(&s_addr[idx], ip, sizeof(ip))) {
        return false;
    }
    esp_tls_cfg_t cfg = {
        .crt_bundle_attach = esp_crt_bundle_attach, /* valida la cadena de CAs */
        .common_name = s_sni[idx],                  /* el cert debe casar el hostname */
        .timeout_ms = DOT_CONNECT_TMO_MS,
    };
    esp_tls_t *tls = esp_tls_init();
    if (tls == NULL) {
        return false;
    }
    /* Conecta por IP LITERAL (no hostname) ⇒ sin bootstrap DNS en claro (R1). */
    int r = esp_tls_conn_new_sync(ip, (int)strlen(ip), DOT_PORT, &cfg, tls);
    if (r != 1) {
        esp_tls_conn_destroy(tls);
        snprintf(s_last_error, sizeof(s_last_error), "conexion %.46s (%.46s) fallo",
                 s_sni[idx], ip);
        ESP_LOGW(TAG, "%s", s_last_error);
        return false;
    }
    /* acota lecturas a nivel de socket (defensa extra al deadline por SW) */
    int fd = -1;
    if (esp_tls_get_conn_sockfd(tls, &fd) == ESP_OK && fd >= 0) {
        struct timeval tv = {.tv_sec = DOT_IO_TMO_MS / 1000,
                             .tv_usec = (DOT_IO_TMO_MS % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    s_tls = tls;
    s_conn_idx = idx;
    s_connected = true;
    ESP_LOGI(TAG, "DoT conectado a %s (%s):%d", s_sni[idx], ip, DOT_PORT);
    return true;
}

/* ¿es un valor de retorno de esp_tls que solo pide reintentar? */
static bool tls_retryable(ssize_t r)
{
    return r == ESP_TLS_ERR_SSL_WANT_READ || r == ESP_TLS_ERR_SSL_WANT_WRITE;
}

static bool write_all(esp_tls_t *tls, const uint8_t *buf, size_t n)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)DOT_IO_TMO_MS * 1000;
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = esp_tls_conn_write(tls, buf + sent, n - sent);
        if (r > 0) {
            sent += (size_t)r;
            continue;
        }
        if (tls_retryable(r) && esp_timer_get_time() < deadline) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        return false; /* 0 = cerrada, <0 = error/timeout */
    }
    return true;
}

static bool read_exact(esp_tls_t *tls, uint8_t *buf, size_t n)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)DOT_IO_TMO_MS * 1000;
    size_t got = 0;
    while (got < n) {
        ssize_t r = esp_tls_conn_read(tls, buf + got, n - got);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (tls_retryable(r) && esp_timer_get_time() < deadline) {
            vTaskDelay(pdMS_TO_TICKS(5));
            continue;
        }
        return false;
    }
    return true;
}

/* Envía SERVFAIL local al cliente (fail-closed): NUNCA reenvía en claro. */
static void send_servfail(const dot_item_t *item)
{
    static uint8_t sf[ESPHOLE_RESP_MAX];
    size_t n = dns_wire_build_rcode_response(&item->q, DNS_RCODE_SERVFAIL, sf,
                                             sizeof(sf));
    if (n > 0) {
        net_dns_send_response(&item->q.client_addr, item->q.client_port, sf, n);
    }
    s_servfail++;
}

/* Un intento contra el upstream idx: conecta/reusa, envía, lee, valida, sirve.
 * true = respuesta entregada al cliente. false = error. */
static bool try_once(int idx, const dot_item_t *item, const uint8_t *framed,
                     size_t flen)
{
    if (!ensure_connected(idx)) {
        return false;
    }
    if (!write_all(s_tls, framed, flen)) {
        return false;
    }
    uint8_t lenp[2];
    if (!read_exact(s_tls, lenp, 2)) {
        return false;
    }
    size_t rlen = ((size_t)lenp[0] << 8) | lenp[1];
    if (rlen < 12 || rlen > ESPHOLE_RESP_MAX) {
        return false; /* respuesta absurda: cierra y failover */
    }
    static uint8_t resp[ESPHOLE_RESP_MAX];
    if (!read_exact(s_tls, resp, rlen)) {
        return false;
    }
    if (!dot_response_ok(item->raw, item->q.raw_len, resp, rlen)) {
        /* resolvedor defectuoso/respuesta inyectada: no la sirvas (FR-010) */
        snprintf(s_last_error, sizeof(s_last_error), "respuesta no casa (%.63s)",
                 s_sni[idx]);
        return false;
    }
    net_dns_send_response(&item->q.client_addr, item->q.client_port, resp, rlen);
    net_dns_cache_put_task(&item->q, resp, rlen);
    s_served++;
    s_last_error[0] = '\0';
    return true;
}

/* Resuelve por idx. Si falla REUSANDO una conexión viva (posible cierre por
 * inactividad del resolvedor), reconecta al MISMO resolvedor y reintenta una vez
 * antes de rendirse: así un corte por inactividad no dispara un failover
 * innecesario (que costaría otro handshake al saltar a otro resolvedor). */
static bool try_resolve(int idx, const dot_item_t *item, const uint8_t *framed,
                        size_t flen)
{
    bool reused = (s_tls != NULL && s_conn_idx == idx);
    if (try_once(idx, item, framed, flen)) {
        return true;
    }
    if (reused) {
        close_conn(); /* la conexión reutilizada estaba muerta: reconecta e insiste */
        if (try_once(idx, item, framed, flen)) {
            return true;
        }
    }
    return false;
}

static void handle_query(dot_item_t *item)
{
    item->q.raw = item->raw; /* fija el puntero al buffer inline (era transitorio) */

    /* Cortacircuitos: si un ciclo reciente encontró TODOS los resolvedores
     * caídos, fail-closed YA (SERVFAIL inmediato) sin re-intentar handshakes ni
     * martillar. Se rearma solo tras el backoff. */
    if (s_alldown_until > esp_timer_get_time()) {
        send_servfail(item);
        return;
    }

    static uint8_t framed[2 + NET_DNS_MAX_QUERY];
    size_t flen = dot_frame_prefix(item->raw, item->q.raw_len, framed, sizeof(framed));
    if (flen == 0) {
        send_servfail(item);
        return;
    }

    /* prueba cada resolvedor cifrado una vez, arrancando por el activo (failover).
     * Corta si nos están parando: durante un stop/reload el forward ya volvió a
     * UDP, así que abandonar esta consulta en vuelo es seguro (el cliente
     * reintenta por UDP) y hace el join de la tarea rápido. */
    for (int tries = 0; tries < s_count && !s_stop; tries++) {
        int idx = (s_active >= 0) ? s_active : 0;
        if (try_resolve(idx, item, framed, flen)) {
            s_active = idx;        /* pega en el que funciona */
            s_alldown_until = 0;   /* hay al menos uno vivo */
            return;
        }
        close_conn();
        s_active = (idx + 1) % s_count; /* siguiente resolvedor cifrado */
    }
    if (s_stop) {
        return; /* parando: no respondas nada; el cliente ya tiene UDP */
    }
    /* ninguno cifrado respondió ⇒ fail-closed + arma el cortacircuitos: las
     * siguientes consultas fail-closed al instante (sin bloquear con un sleep). */
    send_servfail(item);
    s_alldown_until = esp_timer_get_time() + (int64_t)DOT_BACKOFF_MS * 1000;
}

static void dot_task(void *arg)
{
    (void)arg;
    /* Pre-calienta la conexión (handshake TLS anticipado) para que la PRIMERA
     * consulta real no pague ni el handshake ni el failover: busca un resolvedor
     * cifrado VIVO saltando primarios caídos y deja s_active en él. Si ninguno
     * conecta (red aún no lista, :853 filtrado), no pasa nada: la primera
     * consulta reintentará (y hará fail-closed si sigue sin haber ninguno). */
    for (int i = 0; i < s_count && !s_stop; i++) {
        int idx = (s_active + i) % s_count;
        if (ensure_connected(idx)) {
            s_active = idx;
            ESP_LOGI(TAG, "conexion DoT pre-calentada (upstream %d)", idx);
            break;
        }
        close_conn();
    }
    if (s_tls == NULL && !s_stop) {
        /* ninguno conectó al arrancar: arma el cortacircuitos para que la primera
         * consulta fail-closed al instante en vez de repetir todos los handshakes. */
        s_alldown_until = esp_timer_get_time() + (int64_t)DOT_BACKOFF_MS * 1000;
    }
    dot_item_t item;
    while (!s_stop) {
        if (xQueueReceive(s_queue, &item, pdMS_TO_TICKS(500)) == pdTRUE) {
            handle_query(&item);
        }
    }
    close_conn();
    s_running = false;
    xSemaphoreGive(s_done); /* despierta a net_dot_stop (join) */
    vTaskDelete(NULL);
}

/* forward registrado en net_dns: corre en el hilo tcpip, solo encola. */
static void dot_submit(const dns_query_t *q)
{
    if (s_queue == NULL || q->raw == NULL || q->raw_len < 12 ||
        q->raw_len > NET_DNS_MAX_QUERY) {
        return;
    }
    s_scratch.q = *q;
    memcpy(s_scratch.raw, q->raw, q->raw_len);
    s_scratch.q.raw = NULL; /* se recompone en la tarea */
    if (xQueueSend(s_queue, &s_scratch, 0) != pdTRUE) {
        s_dropped++; /* cola llena ⇒ descarta (FR-007); el cliente reintenta */
    }
}

/* --- API --- */

bool net_dot_start(void)
{
    bool enabled = false;
    char sni[CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX];
    config_get_dot(&enabled, sni);
    if (!enabled) {
        net_dot_stop(); /* asegura apagado (idempotente) */
        return true;
    }

    /* reinicio si ya estaba corriendo (reload tras cambio en la web) */
    if (s_running) {
        net_dot_stop();
    }

    esphole_config_t cfg;
    config_load(&cfg);
    s_count = (int)cfg.upstream_count;
    if (s_count <= 0 || s_count > CONFIG_UPSTREAMS_MAX) {
        s_count = CONFIG_UPSTREAMS_MAX;
    }
    for (int i = 0; i < s_count; i++) {
        s_addr[i] = cfg.upstream_addr[i];
        strlcpy(s_sni[i], sni[i], DOT_SNI_MAX);
    }
    s_active = 0;
    s_connected = false;
    s_alldown_until = 0;
    s_served = s_servfail = s_dropped = 0;
    s_last_error[0] = '\0';

    if (s_queue == NULL) {
        s_queue = xQueueCreate(DOT_QUEUE_DEPTH, sizeof(dot_item_t));
        if (s_queue == NULL) {
            ESP_LOGE(TAG, "sin memoria para la cola DoT");
            return false;
        }
    } else {
        xQueueReset(s_queue);
    }

    if (s_done == NULL) {
        static StaticSemaphore_t done_mem;
        s_done = xSemaphoreCreateBinaryStatic(&done_mem);
    }
    xSemaphoreTake(s_done, 0); /* drena señales viejas: el próximo join espera de verdad */

    s_stop = false;
    s_running = true;
    if (xTaskCreate(dot_task, "net_dot", DOT_TASK_STACK, NULL, 5, &s_task) != pdPASS) {
        s_running = false;
        ESP_LOGE(TAG, "no se pudo crear la tarea DoT");
        return false;
    }

    /* conmuta el forward de net_dns a DoT (guardando el UDP para restaurar) */
    s_saved_forward = net_dns_get_forward();
    net_dns_set_forward(dot_submit);
    ESP_LOGI(TAG, "DoT activo: %d resolvedor(es), forward conmutado", s_count);
    return true;
}

void net_dot_stop(void)
{
    if (!s_running) {
        return;
    }
    /* restaura el forward UDP ANTES de parar la tarea: las consultas nuevas
     * vuelven de inmediato a la ruta en claro sin encolarse en una cola muerta. */
    net_dns_set_forward(s_saved_forward);
    s_saved_forward = NULL;

    s_stop = true;
    /* JOIN fiable: espera a que la tarea salga de verdad. Puede estar dentro de
     * un handshake/IO TLS bloqueante de varios segundos; el chequeo de s_stop en
     * el bucle de failover acota esa espera. Sin este join, un reload rápido
     * podría crear una segunda tarea compitiendo por s_tls/la cola. */
    if (s_done != NULL && xSemaphoreTake(s_done, pdMS_TO_TICKS(15000)) != pdTRUE) {
        ESP_LOGE(TAG, "la tarea DoT no salió a tiempo (join)");
    }
    s_active = -1;
    s_connected = false;
    ESP_LOGI(TAG, "DoT desactivado: forward restaurado a UDP");
}

void net_dot_status(net_dot_status_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->enabled = s_running;
    out->connected = s_connected;
    out->active = s_running ? s_active : -1;
    out->served = s_served;
    out->servfail = s_servfail;
    out->dropped = s_dropped;
    strlcpy(out->last_error, s_last_error, sizeof(out->last_error));
}
