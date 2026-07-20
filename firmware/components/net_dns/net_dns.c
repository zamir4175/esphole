#include "net_dns.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"

#include "dns_wire.h"
#include "domain.h"
#include "metrics.h"
#include "ratelimit.h"

static const char *TAG = "net_dns";

static const esphole_config_t *s_cfg;
static const policy_t *s_policy;
static blocklist_t *s_bl;
static cache_t *s_cache;
static ratelimit_t s_rl;
static clients_t s_clients; /* registro por IP (spec 008); solo se muta en tcpip */
static struct udp_pcb *s_pcb;
static net_dns_forward_fn s_forward;

/* buffers estáticos: el callback raw corre serializado en el hilo tcpip,
 * así no se carga su pila (P-II) */
static uint8_t s_rx[NET_DNS_MAX_QUERY];
static uint8_t s_tx[NET_DNS_MAX_QUERY + 64];

static uint32_t ms_now(void) { return (uint32_t)(esp_timer_get_time() / 1000); }
static uint32_t s_now(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

static void desde_lwip(const ip_addr_t *a, ip_addr16_t *out)
{
    memset(out, 0, sizeof(*out));
    if (IP_IS_V4(a)) {
        out->family = ESPHOLE_AF_V4;
        uint32_t v = lwip_htonl(ip4_addr_get_u32(ip_2_ip4(a)));
        out->bytes[0] = (uint8_t)(v >> 24);
        out->bytes[1] = (uint8_t)(v >> 16);
        out->bytes[2] = (uint8_t)(v >> 8);
        out->bytes[3] = (uint8_t)v;
    } else {
        out->family = ESPHOLE_AF_V6;
        const ip6_addr_t *s = ip_2_ip6(a);
        for (int g = 0; g < 4; g++) {
            uint32_t w = lwip_htonl(s->addr[g]);
            out->bytes[g * 4] = (uint8_t)(w >> 24);
            out->bytes[g * 4 + 1] = (uint8_t)(w >> 16);
            out->bytes[g * 4 + 2] = (uint8_t)(w >> 8);
            out->bytes[g * 4 + 3] = (uint8_t)w;
        }
    }
}

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

/* envío dentro del callback (ya en contexto tcpip: sin lock) */
static void envia_inline(const ip_addr_t *addr, u16_t port, const uint8_t *resp,
                         size_t len)
{
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (p == NULL) {
        return; /* sin memoria: el cliente reintentará (nunca colgarse) */
    }
    memcpy(p->payload, resp, len);
    udp_sendto(s_pcb, p, addr, port);
    pbuf_free(p);
}

void net_dns_send_from_tcpip(const ip_addr16_t *dst, uint16_t port,
                             const uint8_t *resp, size_t len)
{
    if (s_pcb == NULL || dst == NULL || resp == NULL) {
        return;
    }
    ip_addr_t a;
    hacia_lwip(dst, &a);
    envia_inline(&a, port, resp, len);
}

bool net_dns_send_response(const ip_addr16_t *dst, uint16_t port,
                           const uint8_t *resp, size_t len)
{
    if (s_pcb == NULL || dst == NULL || resp == NULL) {
        return false;
    }
    ip_addr_t a;
    hacia_lwip(dst, &a);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (p == NULL) {
        return false;
    }
    memcpy(p->payload, resp, len);
    LOCK_TCPIP_CORE(); /* R1: envío desde otra tarea con core-locking */
    err_t e = udp_sendto(s_pcb, p, &a, port);
    UNLOCK_TCPIP_CORE();
    pbuf_free(p);
    return e == ERR_OK;
}

/*
 * Camino rápido compartido UDP/TCP (misma ruta de resolución, FR-014).
 * Corre SOLO en el hilo tcpip: NUNCA bloquea, NUNCA espera al upstream.
 */
static net_dns_verdict_t fastpath(const uint8_t *query, size_t qlen,
                                  const ip_addr16_t *src, uint16_t src_port,
                                  uint8_t transport, uint8_t *out,
                                  size_t out_cap, size_t *out_len,
                                  dns_query_t *q)
{
    int64_t t0 = esp_timer_get_time();
    *out_len = 0;

    if (!policy_is_local(s_policy, src)) {
        metrics_inc(MET_NO_LOCALES); /* no-resolvedor-abierto (R6) */
        return NET_DNS_DROP;
    }
    if (qlen < 12 || qlen > NET_DNS_MAX_QUERY) {
        metrics_inc(MET_MALFORMADAS);
        return NET_DNS_DROP;
    }
    dns_wire_err_t err = dns_wire_parse_query(query, qlen, q);
    if (err == DNS_WIRE_MALFORMED) {
        metrics_inc(MET_MALFORMADAS); /* antes del bucket (R6) */
        return NET_DNS_DROP;
    }
    if (!ratelimit_check(&s_rl, src, ms_now())) {
        metrics_inc(MET_RATELIMITED); /* descarte silencioso (CB-42) */
        return NET_DNS_DROP;
    }
    metrics_inc(MET_TOTAL);
    q->client_addr = *src;
    q->client_port = src_port;
    q->transport = transport;

    if (err == DNS_WIRE_UNSUPPORTED) {
        /* bien formada pero no procesable: reenvío íntegro (FR-006) */
        q->raw = query;
        q->raw_len = (uint16_t)qlen;
        q->qname_len = 0;
        clients_record(&s_clients, src, false, s_now()); /* cliente: consulta reenviada */
        return NET_DNS_FORWARD;
    }

    /* 1) ¿bloqueado? */
    char inv[ESPHOLE_DOMAIN_MAX + 1];
    int il = domain_normalize_invert(q->qname, q->qname_len, inv);
    if (il > 0 && blocklist_contains(s_bl, inv, (size_t)il)) {
        size_t n = dns_wire_build_block_response(q, s_cfg->block_ttl, out, out_cap);
        if (n > 0) {
            *out_len = n;
            metrics_inc(MET_BLOQUEADAS);
            clients_record(&s_clients, src, true, s_now()); /* cliente: bloqueada */
            metrics_latencia_inline_us((uint32_t)(esp_timer_get_time() - t0));
            return NET_DNS_RESP;
        }
        /* no se pudo construir: fail-open ⇒ sigue como miss (P-I) */
    }

    /* cliente: consulta permitida (acierto de caché o reenvío) */
    clients_record(&s_clients, src, false, s_now());

    /* 2) ¿en caché? */
    size_t n = cache_get(s_cache, q, s_now(), out, out_cap);
    if (n > 0) {
        *out_len = n;
        metrics_inc(MET_CACHE_HITS);
        metrics_latencia_inline_us((uint32_t)(esp_timer_get_time() - t0));
        return NET_DNS_RESP;
    }

    return NET_DNS_FORWARD; /* 3) miss ⇒ camino asíncrono */
}

static void recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                    const ip_addr_t *addr, u16_t port)
{
    (void)arg;
    (void)pcb;
    do {
        if (p->tot_len > NET_DNS_MAX_QUERY) {
            metrics_inc(MET_MALFORMADAS);
            break;
        }
        pbuf_copy_partial(p, s_rx, p->tot_len, 0);
        ip_addr16_t src;
        desde_lwip(addr, &src);

        dns_query_t q;
        size_t n = 0;
        net_dns_verdict_t v = fastpath(s_rx, p->tot_len, &src, port,
                                       ESPHOLE_TRANSPORT_UDP, s_tx,
                                       sizeof(s_tx), &n, &q);
        if (v == NET_DNS_RESP) {
            envia_inline(addr, port, s_tx, n);
        } else if (v == NET_DNS_FORWARD) {
            if (s_forward != NULL) {
                s_forward(&q);
            } else {
                /* sin upstream registrado = todos caídos (P-I) */
                size_t m = dns_wire_build_rcode_response(&q, DNS_RCODE_SERVFAIL,
                                                         s_tx, sizeof(s_tx));
                if (m > 0) {
                    envia_inline(addr, port, s_tx, m);
                }
                metrics_inc(MET_SERVFAIL);
            }
        }
    } while (0);
    pbuf_free(p);
}

/* ---- puente para el listener TCP: salta al hilo tcpip y espera ---- */

struct resolve_msg {
    const uint8_t *query;
    size_t qlen;
    const ip_addr16_t *src;
    uint16_t src_port;
    uint8_t *out;
    size_t out_cap;
    size_t out_len;
    dns_query_t *q_out;
    net_dns_verdict_t verdict;
    SemaphoreHandle_t done;
};

static void resolve_en_tcpip(void *ctx)
{
    struct resolve_msg *m = ctx;
    m->verdict = fastpath(m->query, m->qlen, m->src, m->src_port,
                          ESPHOLE_TRANSPORT_TCP, m->out, m->out_cap,
                          &m->out_len, m->q_out);
    xSemaphoreGive(m->done);
}

net_dns_verdict_t net_dns_resolve_for_tcp(const uint8_t *query, size_t qlen,
                                          const ip_addr16_t *src,
                                          uint16_t src_port, uint8_t *out,
                                          size_t out_cap, size_t *out_len,
                                          dns_query_t *q_out)
{
    static StaticSemaphore_t sem_mem; /* un solo llamador (tarea TCP) */
    struct resolve_msg m = {
        .query = query,
        .qlen = qlen,
        .src = src,
        .src_port = src_port,
        .out = out,
        .out_cap = out_cap,
        .q_out = q_out,
        .verdict = NET_DNS_DROP,
        .done = xSemaphoreCreateBinaryStatic(&sem_mem),
    };
    if (tcpip_callback(resolve_en_tcpip, &m) != ERR_OK) {
        return NET_DNS_DROP;
    }
    xSemaphoreTake(m.done, portMAX_DELAY);
    *out_len = m.out_len;
    return m.verdict;
}

void net_dns_set_forward(net_dns_forward_fn fn) { s_forward = fn; }

net_dns_forward_fn net_dns_get_forward(void) { return s_forward; }

/* --- Registro de clientes (spec 008): instantánea/reinicio en el hilo tcpip --- */

struct clients_snap_msg {
    client_ent_t *out;
    size_t cap;
    size_t n;
    SemaphoreHandle_t done;
};

static void clients_snap_en_tcpip(void *ctx)
{
    struct clients_snap_msg *m = ctx;
    m->n = clients_snapshot(&s_clients, m->out, m->cap);
    xSemaphoreGive(m->done);
}

size_t net_dns_clients_snapshot(client_ent_t *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return 0;
    }
    static StaticSemaphore_t sem_mem; /* un solo llamador serie (tarea HTTP) */
    struct clients_snap_msg m = {
        .out = out,
        .cap = cap,
        .n = 0,
        .done = xSemaphoreCreateBinaryStatic(&sem_mem),
    };
    if (tcpip_callback(clients_snap_en_tcpip, &m) != ERR_OK) {
        return 0;
    }
    xSemaphoreTake(m.done, portMAX_DELAY);
    return m.n;
}

static void clients_reset_en_tcpip(void *ctx)
{
    SemaphoreHandle_t done = ctx;
    clients_reset(&s_clients);
    xSemaphoreGive(done);
}

void net_dns_clients_reset(void)
{
    static StaticSemaphore_t sem_mem;
    SemaphoreHandle_t done = xSemaphoreCreateBinaryStatic(&sem_mem);
    if (tcpip_callback(clients_reset_en_tcpip, done) != ERR_OK) {
        return;
    }
    xSemaphoreTake(done, portMAX_DELAY);
}

/* --- Caché desde otra tarea (spec 007: tarea DoT) --- */

struct cacheput_msg {
    const dns_query_t *q;
    const uint8_t *resp;
    size_t len;
    SemaphoreHandle_t done;
};

static void cacheput_en_tcpip(void *ctx)
{
    struct cacheput_msg *m = ctx;
    uint32_t ttl;
    if (s_cache != NULL && dns_wire_min_ttl(m->resp, m->len, &ttl)) {
        cache_put(s_cache, m->q, m->resp, m->len, ttl, s_now());
    }
    xSemaphoreGive(m->done);
}

void net_dns_cache_put_task(const dns_query_t *q, const uint8_t *resp, size_t len)
{
    if (s_cache == NULL || q == NULL || resp == NULL || len == 0) {
        return;
    }
    static StaticSemaphore_t sem_mem; /* un solo llamador serie (tarea DoT) */
    struct cacheput_msg m = {
        .q = q,
        .resp = resp,
        .len = len,
        .done = xSemaphoreCreateBinaryStatic(&sem_mem),
    };
    if (tcpip_callback(cacheput_en_tcpip, &m) != ERR_OK) {
        return; /* mejor esfuerzo: si no se pudo encolar, no se cachea */
    }
    xSemaphoreTake(m.done, portMAX_DELAY);
}

/* --- Vaciado/ocupación de la caché para la API (spec 003) --- */

static void flush_en_tcpip(void *ctx)
{
    SemaphoreHandle_t done = ctx;
    cache_clear(s_cache);
    xSemaphoreGive(done);
}

void net_dns_cache_flush(void)
{
    if (s_cache == NULL) {
        return;
    }
    /* la caché solo se muta en el hilo tcpip: el vaciado salta allí y espera,
     * evitando carreras con el camino rápido (P-I: la ruta DNS no se degrada). */
    static StaticSemaphore_t sem_mem;
    SemaphoreHandle_t done = xSemaphoreCreateBinaryStatic(&sem_mem);
    if (tcpip_callback(flush_en_tcpip, done) != ERR_OK) {
        return;
    }
    xSemaphoreTake(done, portMAX_DELAY);
}

uint16_t net_dns_cache_count(void)
{
    return (s_cache != NULL) ? cache_count(s_cache) : 0; /* lectura benigna */
}

static void suspend_en_tcpip(void *ctx)
{
    SemaphoreHandle_t done = ctx;
    if (s_bl != NULL) {
        s_bl->state = BL_EMPTY; /* fail-open mientras se reconstruye (spec 004) */
    }
    xSemaphoreGive(done);
}

void net_dns_blocklist_suspend(void)
{
    if (s_bl == NULL) {
        return;
    }
    static StaticSemaphore_t sem_mem;
    SemaphoreHandle_t done = xSemaphoreCreateBinaryStatic(&sem_mem);
    if (tcpip_callback(suspend_en_tcpip, done) != ERR_OK) {
        s_bl->state = BL_EMPTY; /* mejor esfuerzo: aún así suspende */
        return;
    }
    xSemaphoreTake(done, portMAX_DELAY);
}

bool net_dns_start(const esphole_config_t *cfg, const policy_t *pol,
                   blocklist_t *bl, cache_t *cache)
{
    if (cfg == NULL || pol == NULL || bl == NULL || cache == NULL) {
        return false;
    }
    s_cfg = cfg;
    s_policy = pol;
    s_bl = bl;
    s_cache = cache;
    clients_init(&s_clients); /* registro por IP vacío al arrancar (efímero) */
    ratelimit_init(&s_rl, cfg->rl_ip_rate, cfg->rl_ip_burst, cfg->rl_glob_rate,
                   cfg->rl_glob_burst);

    LOCK_TCPIP_CORE();
    s_pcb = udp_new_ip_type(IPADDR_TYPE_ANY); /* v4 + v6 (P-III) */
    err_t e = ERR_MEM;
    if (s_pcb != NULL) {
        e = udp_bind(s_pcb, IP_ANY_TYPE, 53);
        if (e == ERR_OK) {
            udp_recv(s_pcb, recv_cb, NULL);
        }
    }
    UNLOCK_TCPIP_CORE();

    if (e != ERR_OK) {
        ESP_LOGE(TAG, "no se pudo enlazar el puerto 53 (err %d)", e);
        return false;
    }
    ESP_LOGI(TAG, "listener UDP :53 activo (raw lwIP, camino rápido inline)");
    return true;
}
