#include "upstream.h"

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/udp.h"

#include "dns_wire.h"
#include "metrics.h"
#include "net_dns.h"
#include "pending.h"

static const char *TAG = "upstream";

#define RX_MAX 1536
#define BACKOFF_MS 30000 /* sondeo de un upstream CAIDO (FR-011) */
#define RAW_ENTRIES 8    /* passthrough de consultas UNSUPPORTED (FR-006) */

static const esphole_config_t *s_cfg;
static cache_t *s_cache;
static struct udp_pcb *s_pcb; /* hacia los upstreams (puerto efímero propio) */
static pending_table_t s_pend;
static esp_timer_handle_t s_timer;

/* salud por upstream (FR-011): solo se toca en el hilo tcpip */
static struct {
    uint8_t fallos;
    uint32_t caido_hasta_ms;
} s_salud[CONFIG_UPSTREAMS_MAX];

/* passthrough de consultas bien formadas pero no procesables (CB-17) */
static struct {
    bool en_uso;
    uint16_t txid_upstream, txid_cliente;
    ip_addr16_t cliente;
    uint16_t puerto;
    uint32_t enviado_ms;
} s_raw[RAW_ENTRIES];

static uint8_t s_rx[RX_MAX];
static uint8_t s_tx[RX_MAX];

static uint32_t ms_now(void) { return (uint32_t)(esp_timer_get_time() / 1000); }
static uint32_t s_now(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }
static uint16_t rand16(void) { return (uint16_t)esp_random(); }

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

static bool addr_es_upstream(const ip_addr_t *src, uint16_t port, uint8_t idx)
{
    if (idx >= s_cfg->upstream_count || port != s_cfg->upstream_port[idx]) {
        return false;
    }
    ip_addr_t esperado;
    hacia_lwip(&s_cfg->upstream_addr[idx], &esperado);
    return ip_addr_cmp(&esperado, src);
}

/* primer upstream utilizable desde 'desde' (salud, con sondeo tras backoff) */
static uint8_t elegir(uint8_t desde, uint32_t now)
{
    for (uint8_t i = 0; i < s_cfg->upstream_count; i++) {
        uint8_t idx = (uint8_t)((desde + i) % s_cfg->upstream_count);
        if (s_salud[idx].fallos < 3) {
            return idx;
        }
        if ((int32_t)(now - s_salud[idx].caido_hasta_ms) >= 0) {
            /* CAIDO pero toca sondear: se usa tráfico real (FR-011) */
            s_salud[idx].caido_hasta_ms = now + BACKOFF_MS;
            return idx;
        }
    }
    return desde % s_cfg->upstream_count; /* todos caídos: intentar igual (P-I) */
}

static void salud_fallo(uint8_t idx, uint32_t now)
{
    if (idx >= CONFIG_UPSTREAMS_MAX) {
        return;
    }
    if (s_salud[idx].fallos < 3) {
        s_salud[idx].fallos++;
        if (s_salud[idx].fallos == 3) {
            s_salud[idx].caido_hasta_ms = now + BACKOFF_MS;
            ESP_LOGW(TAG, "upstream %u CAIDO (sondeo en %u ms)", idx, BACKOFF_MS);
        }
    }
    metrics_upstream_fallo(idx);
}

static void salud_ok(uint8_t idx)
{
    if (idx < CONFIG_UPSTREAMS_MAX && s_salud[idx].fallos != 0) {
        ESP_LOGI(TAG, "upstream %u recuperado", idx);
        s_salud[idx].fallos = 0;
    }
}

static void envia_a(uint8_t idx, const uint8_t *buf, size_t len)
{
    ip_addr_t dst;
    hacia_lwip(&s_cfg->upstream_addr[idx], &dst);
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (p == NULL) {
        return;
    }
    memcpy(p->payload, buf, len);
    udp_sendto(s_pcb, p, &dst, s_cfg->upstream_port[idx]);
    pbuf_free(p);
}

/* ---- envío de una clave (primer intento y reintentos) ---- */
static void envia_clave(const char *qname, uint8_t qname_len, uint16_t qtype,
                        uint16_t qclass, uint16_t txid, uint8_t idx)
{
    size_t n = dns_wire_build_query(qname, qname_len, qtype, qclass, txid,
                                    true /* EDNS hacia upstream (R4) */, s_tx,
                                    sizeof(s_tx));
    if (n > 0) {
        envia_a(idx, s_tx, n);
    }
}

/* ---- forward registrado en net_dns: corre en el hilo tcpip ---- */
static void submit(const dns_query_t *q)
{
    uint32_t now = ms_now();

    if (q->qname_len == 0) {
        /* UNSUPPORTED: passthrough íntegro con txid propio (FR-006) */
        if (q->raw == NULL || q->raw_len < 12 || q->raw_len > sizeof(s_tx)) {
            return;
        }
        int slot = -1;
        for (int i = 0; i < RAW_ENTRIES; i++) {
            if (!s_raw[i].en_uso) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            metrics_inc(MET_PENDING_OVERFLOW);
            return; /* tabla mini llena: el cliente reintentará */
        }
        uint8_t idx = elegir(0, now);
        memcpy(s_tx, q->raw, q->raw_len);
        uint16_t txid = rand16();
        dns_wire_rewrite_id(s_tx, q->raw_len, txid);
        s_raw[slot].en_uso = true;
        s_raw[slot].txid_upstream = txid;
        s_raw[slot].txid_cliente = q->id;
        s_raw[slot].cliente = q->client_addr;
        s_raw[slot].puerto = q->client_port;
        s_raw[slot].enviado_ms = now;
        envia_a(idx, s_tx, q->raw_len);
        return;
    }

    uint8_t idx = elegir(0, now);
    uint16_t txid = 0;
    pending_verdict_t v = pending_register(&s_pend, q, idx, now, &txid);
    if (v == PENDING_GROUPED) {
        return; /* ya hay una en vuelo para esta clave (CB-55) */
    }
    if (v == PENDING_SEND_SOLO) {
        metrics_inc(MET_PENDING_OVERFLOW);
    }
    envia_clave(q->qname, q->qname_len, q->qtype, q->qclass, txid, idx);
}

/* ---- fan-out de una respuesta a los waiters ---- */
static void fan_out(const pending_waiters_t *w, const uint8_t *resp, size_t len)
{
    for (uint8_t i = 0; i < w->count; i++) {
        const pending_waiter_t *cl = &w->w[i];
        size_t limite =
            cl->edns_present
                ? ((cl->edns_payload < 512) ? 512 : cl->edns_payload)
                : 512;
        if (len > sizeof(s_tx)) {
            continue;
        }
        memcpy(s_tx, resp, len);
        size_t n = len;
        if (n > limite) {
            n = dns_wire_truncate(s_tx, n, limite); /* TC=1 → TCP (CB-31) */
            if (n == 0) {
                continue;
            }
        }
        dns_wire_rewrite_id(s_tx, n, cl->id_original);
        net_dns_send_from_tcpip(&cl->addr, cl->port, s_tx, n);
        metrics_inc(MET_REENVIADAS);
    }
}

/* ---- respuestas upstream: callback raw, hilo tcpip ---- */
static void up_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                       const ip_addr_t *addr, u16_t port)
{
    (void)arg;
    (void)pcb;
    do {
        if (p->tot_len < 12 || p->tot_len > RX_MAX) {
            break;
        }
        pbuf_copy_partial(p, s_rx, p->tot_len, 0);
        uint16_t txid = (uint16_t)((s_rx[0] << 8) | s_rx[1]);

        /* ¿passthrough raw? */
        for (int i = 0; i < RAW_ENTRIES; i++) {
            if (s_raw[i].en_uso && s_raw[i].txid_upstream == txid) {
                dns_wire_rewrite_id(s_rx, p->tot_len, s_raw[i].txid_cliente);
                net_dns_send_from_tcpip(&s_raw[i].cliente, s_raw[i].puerto,
                                        s_rx, p->tot_len);
                metrics_inc(MET_REENVIADAS);
                s_raw[i].en_uso = false;
                pbuf_free(p);
                return;
            }
        }

        /* validación de origen ANTES de casar (R5, P-V) */
        uint8_t idx;
        if (!pending_upstream_of(&s_pend, txid, &idx) ||
            !addr_es_upstream(addr, port, idx)) {
            break; /* txid desconocido u origen ilegítimo: descartar (CB-44) */
        }
        const pending_waiters_t *w = pending_match(&s_pend, txid, s_rx, p->tot_len);
        if (w == NULL) {
            break; /* la pregunta no casa: envenenamiento descartado */
        }
        salud_ok(idx);
        metrics_latencia_ms(ms_now() - w->enviado_en);

        /* cachear la respuesta reenviada (FR-016; cache_put filtra RCODE/TTL) */
        uint32_t ttl;
        if (dns_wire_min_ttl(s_rx, p->tot_len, &ttl)) {
            dns_query_t clave;
            memset(&clave, 0, sizeof(clave));
            memcpy(clave.qname, w->qname, (size_t)w->qname_len + 1);
            clave.qname_len = w->qname_len;
            clave.qtype = w->qtype;
            clave.qclass = w->qclass;
            cache_put(s_cache, &clave, s_rx, p->tot_len, ttl, s_now());
        }
        fan_out(w, s_rx, p->tot_len);
    } while (0);
    pbuf_free(p);
}

/* ---- timeouts: esp_timer → tcpip_callback → aquí (hilo tcpip) ---- */
/* estático: ~740 B por acción — en la pila del hilo tcpip (3-6 KB) sería un
 * desbordamiento (lo fue: assert en memp_free por corrupción de pila). La
 * ruta es single-threaded, así que el buffer compartido es seguro. */
static pending_action_t s_acts[8];

static void procesa_expiraciones(void *ctx)
{
    (void)ctx;
    uint32_t now = ms_now();
    pending_action_t *acts = s_acts;
    size_t n = pending_expire(&s_pend, now, UPSTREAM_TIMEOUT_MS, acts,
                              sizeof(s_acts) / sizeof(s_acts[0]));
    for (size_t i = 0; i < n; i++) {
        pending_action_t *a = &acts[i];
        if (a->kind == PENDING_ACT_RETRY) {
            /* el que venció es el anterior al sugerido */
            salud_fallo((uint8_t)((a->upstream_idx + s_cfg->upstream_count - 1) %
                                  s_cfg->upstream_count),
                        now);
            uint8_t idx = (uint8_t)(a->upstream_idx % s_cfg->upstream_count);
            envia_clave(a->qname, a->qname_len, a->qtype, a->qclass, a->new_txid,
                        idx);
        } else {
            /* agotado: SERVFAIL a cada waiter (FR-008) */
            salud_fallo((uint8_t)(a->upstream_idx % s_cfg->upstream_count), now);
            size_t qn = dns_wire_build_query(a->qname, a->qname_len, a->qtype,
                                             a->qclass, 0, false, s_tx,
                                             sizeof(s_tx));
            if (qn == 0) {
                continue;
            }
            s_tx[2] |= 0x80; /* QR=1 */
            s_tx[3] = (uint8_t)(0x80 | DNS_RCODE_SERVFAIL);
            for (uint8_t c = 0; c < a->waiters.count; c++) {
                dns_wire_rewrite_id(s_tx, qn, a->waiters.w[c].id_original);
                net_dns_send_from_tcpip(&a->waiters.w[c].addr,
                                        a->waiters.w[c].port, s_tx, qn);
                metrics_inc(MET_SERVFAIL);
            }
        }
    }
    /* expira el passthrough raw en silencio */
    for (int i = 0; i < RAW_ENTRIES; i++) {
        if (s_raw[i].en_uso &&
            (uint32_t)(now - s_raw[i].enviado_ms) > 2 * UPSTREAM_TIMEOUT_MS) {
            s_raw[i].en_uso = false;
        }
    }
}

static void timer_cb(void *arg)
{
    (void)arg;
    /* salta al hilo tcpip: toda la ruta DNS es single-threaded */
    tcpip_callback(procesa_expiraciones, NULL);
}

bool upstream_start(const esphole_config_t *cfg, cache_t *cache)
{
    if (cfg == NULL || cache == NULL || cfg->upstream_count == 0) {
        return false;
    }
    s_cfg = cfg;
    s_cache = cache;

    /* asignación única en init (no en caliente, P-II); tabla en PSRAM */
    void *mem = heap_caps_malloc(pending_mem_size(),
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (mem == NULL) {
        mem = heap_caps_malloc(pending_mem_size(), MALLOC_CAP_8BIT);
    }
    if (mem == NULL) {
        return false;
    }
    pending_init(&s_pend, mem, rand16);

    LOCK_TCPIP_CORE();
    s_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    err_t e = ERR_MEM;
    if (s_pcb != NULL) {
        e = udp_bind(s_pcb, IP_ANY_TYPE, 0); /* puerto efímero aleatorio */
        if (e == ERR_OK) {
            udp_recv(s_pcb, up_recv_cb, NULL);
        }
    }
    UNLOCK_TCPIP_CORE();
    if (e != ERR_OK) {
        ESP_LOGE(TAG, "no se pudo crear el pcb upstream (err %d)", e);
        return false;
    }

    const esp_timer_create_args_t targs = {.callback = timer_cb,
                                           .name = "up_expire"};
    if (esp_timer_create(&targs, &s_timer) != ESP_OK ||
        esp_timer_start_periodic(s_timer, 250 * 1000) != ESP_OK) {
        ESP_LOGE(TAG, "no se pudo crear el timer de expiración");
        return false;
    }

    net_dns_set_forward(submit);
    ESP_LOGI(TAG, "reenvío activo: %u upstreams, timeout %u ms",
             cfg->upstream_count, UPSTREAM_TIMEOUT_MS);
    return true;
}

void upstream_health(uint8_t salud[CONFIG_UPSTREAMS_MAX], uint8_t *count)
{
    /* mapeo de fallos consecutivos → salud para la API (0=sano, 1=sospechoso,
     * 2=caído). Lectura benigna de monitoreo: s_salud solo se muta en tcpip. */
    if (count != NULL) {
        *count = (s_cfg != NULL) ? s_cfg->upstream_count : 0;
    }
    if (salud == NULL) {
        return;
    }
    for (int i = 0; i < CONFIG_UPSTREAMS_MAX; i++) {
        uint8_t f = s_salud[i].fallos;
        salud[i] = (f == 0) ? 0 : (f >= 3 ? 2 : 1);
    }
}
