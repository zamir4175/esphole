/*
 * tcp_dns — listener TCP :53 (RFC 7766) sobre sockets BSD (R1/T026).
 * Framing de prefijo de 2 bytes; hasta TCP_DNS_MAX_CONNS conexiones
 * concurrentes (las excedentes se cierran limpiamente, CB-33); timeout de
 * conexión ociosa. La resolución es la MISMA que UDP (net_dns_resolve_for_tcp
 * salta al hilo tcpip); un miss se resuelve con un intercambio upstream
 * síncrono propio — el volumen TCP es marginal (solo tras bit TC).
 * Limitación v1 documentada: durante ese intercambio (≤2×1.5 s) las demás
 * conexiones TCP esperan; UDP no se ve afectado jamás.
 */
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

#include "dns_wire.h"
#include "metrics.h"
#include "net_dns.h"

static const char *TAG = "tcp_dns";

#define TCP_DNS_MAX_CONNS 4
#define TCP_IDLE_TIMEOUT_MS 5000
#define UP_TIMEOUT_MS 1500
#define UP_RX_MAX 1536

static const esphole_config_t *s_cfg;
static const policy_t *s_policy;

typedef struct {
    int fd;
    ip_addr16_t peer;
    uint16_t peer_port;
    uint8_t buf[2 + NET_DNS_MAX_QUERY];
    size_t have;   /* bytes acumulados (incluye los 2 de longitud) */
    uint32_t ultimo_ms;
} conn_t;

static uint32_t ms_now(void) { return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS); }

static void sockaddr_a_ip16(const struct sockaddr_storage *ss, ip_addr16_t *out,
                            uint16_t *port)
{
    memset(out, 0, sizeof(*out));
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        out->family = ESPHOLE_AF_V4;
        memcpy(out->bytes, &a->sin_addr.s_addr, 4);
        *port = lwip_ntohs(a->sin_port);
    } else {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)ss;
        out->family = ESPHOLE_AF_V6;
        memcpy(out->bytes, a6->sin6_addr.un.u8_addr, 16);
        *port = lwip_ntohs(a6->sin6_port);
    }
}

/* envía respuesta con framing RFC 7766; false si el socket falló */
static bool envia_framed(int fd, const uint8_t *resp, size_t len)
{
    uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    if (lwip_send(fd, hdr, 2, 0) != 2) {
        return false;
    }
    return lwip_send(fd, resp, len, 0) == (ssize_t)len;
}

/*
 * Intercambio upstream síncrono para misses TCP: prueba upstreams en orden
 * con txid aleatorio y validación de origen. No toca la tabla de pendientes
 * ni la caché (viven en el hilo tcpip); volumen marginal.
 */
static size_t upstream_sync(const dns_query_t *q, uint8_t *out, size_t out_cap)
{
    int us = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (us < 0) {
        return 0;
    }
    struct timeval tv = {.tv_sec = UP_TIMEOUT_MS / 1000,
                         .tv_usec = (UP_TIMEOUT_MS % 1000) * 1000};
    lwip_setsockopt(us, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t resultado = 0;
    for (uint8_t i = 0; i < s_cfg->upstream_count && i < 2 && resultado == 0; i++) {
        const ip_addr16_t *up = &s_cfg->upstream_addr[i];
        if (up->family != ESPHOLE_AF_V4) {
            continue; /* el intercambio síncrono v1 usa los upstreams v4 */
        }
        uint16_t txid = (uint16_t)esp_random();
        uint8_t query[NET_DNS_MAX_QUERY];
        size_t qn;
        if (q->qname_len > 0) {
            qn = dns_wire_build_query(q->qname, q->qname_len, q->qtype,
                                      q->qclass, txid, true, query,
                                      sizeof(query));
        } else { /* passthrough de UNSUPPORTED (FR-006) */
            if (q->raw == NULL || q->raw_len > sizeof(query)) {
                break;
            }
            memcpy(query, q->raw, q->raw_len);
            dns_wire_rewrite_id(query, q->raw_len, txid);
            qn = q->raw_len;
        }
        if (qn == 0) {
            break;
        }
        struct sockaddr_in dst = {.sin_family = AF_INET,
                                  .sin_port = lwip_htons(s_cfg->upstream_port[i])};
        memcpy(&dst.sin_addr.s_addr, up->bytes, 4);
        if (lwip_sendto(us, query, qn, 0, (struct sockaddr *)&dst,
                        sizeof(dst)) != (ssize_t)qn) {
            continue;
        }
        struct sockaddr_storage rss;
        socklen_t rlen = sizeof(rss);
        uint8_t rx[UP_RX_MAX];
        ssize_t rn = lwip_recvfrom(us, rx, sizeof(rx), 0,
                                   (struct sockaddr *)&rss, &rlen);
        if (rn < 12) {
            metrics_upstream_fallo(i);
            continue; /* timeout o basura: siguiente upstream (FR-008) */
        }
        /* validación: origen exacto + txid (P-V) */
        ip_addr16_t rsrc;
        uint16_t rport;
        sockaddr_a_ip16(&rss, &rsrc, &rport);
        if (rport != s_cfg->upstream_port[i] ||
            memcmp(rsrc.bytes, up->bytes, 4) != 0 ||
            ((uint16_t)((rx[0] << 8) | rx[1])) != txid) {
            metrics_upstream_fallo(i);
            continue;
        }
        if ((size_t)rn > out_cap) {
            break;
        }
        memcpy(out, rx, (size_t)rn);
        dns_wire_rewrite_id(out, (size_t)rn, q->id);
        resultado = (size_t)rn;
    }
    lwip_close(us);
    return resultado;
}

/* procesa un mensaje completo de la conexión; false ⇒ cerrar conexión */
static bool procesa_mensaje(conn_t *c, const uint8_t *msg, size_t len)
{
    uint8_t out[UP_RX_MAX];
    size_t n = 0;
    dns_query_t q;
    net_dns_verdict_t v = net_dns_resolve_for_tcp(msg, len, &c->peer,
                                                  c->peer_port, out,
                                                  sizeof(out), &n, &q);
    if (v == NET_DNS_RESP) {
        return envia_framed(c->fd, out, n);
    }
    if (v == NET_DNS_DROP) {
        return false; /* malformada: cerrar (FR-009) */
    }
    /* FORWARD: intercambio síncrono; sin respuesta ⇒ SERVFAIL (FR-008) */
    n = upstream_sync(&q, out, sizeof(out));
    if (n > 0) {
        metrics_inc(MET_REENVIADAS);
        return envia_framed(c->fd, out, n);
    }
    if (q.qname_len > 0) {
        n = dns_wire_build_rcode_response(&q, DNS_RCODE_SERVFAIL, out,
                                          sizeof(out));
        metrics_inc(MET_SERVFAIL);
        if (n > 0) {
            return envia_framed(c->fd, out, n);
        }
    }
    return false;
}

static void cierra(conn_t *c)
{
    if (c->fd >= 0) {
        lwip_close(c->fd);
        c->fd = -1;
        c->have = 0;
    }
}

static void tarea_tcp(void *arg)
{
    (void)arg;
    int lfd = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (lfd < 0) {
        ESP_LOGE(TAG, "sin socket de escucha");
        vTaskDelete(NULL);
        return;
    }
    int uno = 1;
    lwip_setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &uno, sizeof(uno));
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_addr.s_addr = INADDR_ANY,
                               .sin_port = lwip_htons(53)};
    if (lwip_bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        lwip_listen(lfd, TCP_DNS_MAX_CONNS) < 0) {
        ESP_LOGE(TAG, "no se pudo escuchar en :53/tcp");
        lwip_close(lfd);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "listener TCP :53 activo (máx %d conexiones)", TCP_DNS_MAX_CONNS);

    static conn_t conns[TCP_DNS_MAX_CONNS];
    for (int i = 0; i < TCP_DNS_MAX_CONNS; i++) {
        conns[i].fd = -1;
    }

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        int maxfd = lfd;
        for (int i = 0; i < TCP_DNS_MAX_CONNS; i++) {
            if (conns[i].fd >= 0) {
                FD_SET(conns[i].fd, &rfds);
                if (conns[i].fd > maxfd) {
                    maxfd = conns[i].fd;
                }
            }
        }
        struct timeval tv = {.tv_sec = 0, .tv_usec = 500 * 1000};
        int r = lwip_select(maxfd + 1, &rfds, NULL, NULL, &tv);
        uint32_t now = ms_now();

        if (r > 0 && FD_ISSET(lfd, &rfds)) {
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            int nfd = lwip_accept(lfd, (struct sockaddr *)&ss, &slen);
            if (nfd >= 0) {
                ip_addr16_t peer;
                uint16_t pport;
                sockaddr_a_ip16(&ss, &peer, &pport);
                int slot = -1;
                for (int i = 0; i < TCP_DNS_MAX_CONNS; i++) {
                    if (conns[i].fd < 0) {
                        slot = i;
                        break;
                    }
                }
                if (slot < 0 || !policy_is_local(s_policy, &peer)) {
                    /* tope alcanzado (CB-33) u origen no local (R6) */
                    lwip_close(nfd);
                    if (slot >= 0) {
                        metrics_inc(MET_NO_LOCALES);
                    }
                } else {
                    conns[slot].fd = nfd;
                    conns[slot].peer = peer;
                    conns[slot].peer_port = pport;
                    conns[slot].have = 0;
                    conns[slot].ultimo_ms = now;
                }
            }
        }

        for (int i = 0; i < TCP_DNS_MAX_CONNS; i++) {
            conn_t *c = &conns[i];
            if (c->fd < 0) {
                continue;
            }
            if (r > 0 && FD_ISSET(c->fd, &rfds)) {
                ssize_t rn = lwip_recv(c->fd, c->buf + c->have,
                                       sizeof(c->buf) - c->have, 0);
                if (rn <= 0) {
                    cierra(c); /* cierre remoto o error */
                    continue;
                }
                c->have += (size_t)rn;
                c->ultimo_ms = now;
                /* procesa todos los mensajes completos acumulados */
                for (;;) {
                    if (c->have < 2) {
                        break;
                    }
                    size_t mlen = ((size_t)c->buf[0] << 8) | c->buf[1];
                    if (mlen < 12 || mlen > NET_DNS_MAX_QUERY) {
                        metrics_inc(MET_MALFORMADAS);
                        cierra(c);
                        break;
                    }
                    if (c->have < 2 + mlen) {
                        break; /* mensaje incompleto: esperar más bytes */
                    }
                    if (!procesa_mensaje(c, c->buf + 2, mlen)) {
                        cierra(c);
                        break;
                    }
                    memmove(c->buf, c->buf + 2 + mlen, c->have - 2 - mlen);
                    c->have -= 2 + mlen;
                }
            } else if ((uint32_t)(now - c->ultimo_ms) > TCP_IDLE_TIMEOUT_MS) {
                cierra(c); /* conexión ociosa */
            }
        }
    }
}

bool net_dns_tcp_start(const esphole_config_t *cfg, const policy_t *pol)
{
    if (cfg == NULL || pol == NULL) {
        return false;
    }
    s_cfg = cfg;
    s_policy = pol;
    return xTaskCreate(tarea_tcp, "tcp_dns", 6144, NULL, 5, NULL) == pdPASS;
}
