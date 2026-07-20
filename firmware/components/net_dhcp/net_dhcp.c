/*
 * net_dhcp — implementación. Ver net_dhcp.h. Servidor DHCP sobre socket UDP :67
 * en su propia tarea. Respuestas en broadcast a 255.255.255.255:68. Sondeo ARP
 * best-effort antes de ofrecer. Toda la lógica de riesgo está en dhcp_wire /
 * dhcp_lease (puros); aquí solo el pegamento con lwIP/esp_netif.
 */
#include "net_dhcp.h"

#include <string.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/def.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"

#include "config_nvs.h"
#include "dhcp_wire.h"

static const char *TAG = "net_dhcp";

#define DHCP_DEFAULT_LEASE_S 7200
#define RECV_TIMEOUT_MS 500
#define BUF_MAX 600

static volatile bool s_run;
static TaskHandle_t s_task;
static int s_sock = -1;
static bool s_enabled;
static dhcp_pool_t s_pool;
static dhcp_leases_t s_leases;
static struct netif *s_netif; /* netif lwIP de la STA, para ARP */
static uint8_t s_rx[BUF_MAX];
static uint8_t s_tx[BUF_MAX];

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

/* --- envío/ARP --- */

static void enviar_broadcast(size_t len)
{
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = lwip_htons(68);
    dst.sin_addr.s_addr = 0xFFFFFFFFu; /* 255.255.255.255 */
    lwip_sendto(s_sock, s_tx, len, 0, (struct sockaddr *)&dst, sizeof(dst));
}

/* ¿la IP (orden de host) parece libre en la red? Best-effort vía ARP. */
static bool arp_libre(uint32_t ip_host)
{
    if (s_netif == NULL) {
        return true; /* sin netif no podemos sondear: confiamos en la tabla */
    }
    ip4_addr_t a;
    a.addr = lwip_htonl(ip_host);
    struct eth_addr *eth = NULL;
    const ip4_addr_t *ret = NULL;
    if (etharp_find_addr(s_netif, &a, &eth, &ret) >= 0) {
        return false; /* ya en la tabla ARP ⇒ en uso */
    }
    etharp_request(s_netif, &a);
    vTaskDelay(pdMS_TO_TICKS(40));
    if (etharp_find_addr(s_netif, &a, &eth, &ret) >= 0) {
        return false; /* respondió ⇒ en uso */
    }
    return true;
}

static void rellena_reply(dhcp_reply_t *r, uint8_t tipo, const dhcp_request_t *req,
                          uint32_t yiaddr)
{
    r->msgtype = tipo;
    r->xid = req->xid;
    r->flags = req->flags;
    r->yiaddr = yiaddr;
    r->mac = req->mac;
    r->server_id = s_pool.own_ip;
    r->mask = s_pool.mask;
    r->gateway = s_pool.gateway;
    r->dns = s_pool.dns;
    r->lease_time = s_pool.lease_time;
}

static void procesar(const dhcp_request_t *req)
{
    uint32_t now = now_s();
    dhcp_reply_t r;
    size_t len;

    switch (req->msgtype) {
    case DHCP_DISCOVER: {
        uint32_t ip = dhcp_lease_offer(&s_leases, &s_pool, req->mac,
                                       req->requested_ip, now);
        /* sondeo ARP: si la IP está en uso, decártala y prueba otra (una vez) */
        if (ip != 0 && !arp_libre(ip)) {
            dhcp_lease_decline(&s_leases, ip);
            ip = dhcp_lease_offer(&s_leases, &s_pool, req->mac, 0, now);
            if (ip != 0 && !arp_libre(ip)) {
                dhcp_lease_decline(&s_leases, ip);
                ip = 0;
            }
        }
        if (ip == 0) {
            return; /* pool lleno / sin libre: no se ofrece */
        }
        rellena_reply(&r, DHCP_OFFER, req, ip);
        len = dhcp_build(&r, s_tx, sizeof(s_tx));
        if (len) {
            enviar_broadcast(len);
            ESP_LOGI(TAG, "OFFER %u.%u.%u.%u", (unsigned)(ip >> 24) & 0xff,
                     (unsigned)(ip >> 16) & 0xff, (unsigned)(ip >> 8) & 0xff,
                     (unsigned)ip & 0xff);
        }
        break;
    }
    case DHCP_REQUEST: {
        /* si el cliente eligió otro servidor, ignorar */
        if (req->server_id != 0 && req->server_id != s_pool.own_ip) {
            return;
        }
        uint32_t ip = (req->requested_ip != 0) ? req->requested_ip : req->ciaddr;
        bool ok = dhcp_lease_commit(&s_leases, &s_pool, req->mac, ip, now,
                                    req->hostname[0] ? req->hostname : NULL);
        rellena_reply(&r, ok ? DHCP_ACK : DHCP_NAK, req, ok ? ip : 0);
        len = dhcp_build(&r, s_tx, sizeof(s_tx));
        if (len) {
            enviar_broadcast(len);
        }
        break;
    }
    case DHCP_RELEASE:
        dhcp_lease_release(&s_leases, req->mac, req->ciaddr);
        break;
    case DHCP_DECLINE:
        dhcp_lease_decline(&s_leases, req->requested_ip);
        break;
    default:
        break; /* INFORM y otros: ignorar */
    }
}

/* --- tarea --- */

static void tarea_dhcp(void *arg)
{
    (void)arg;
    int s = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s < 0) {
        ESP_LOGE(TAG, "socket() falló");
        s_task = NULL;
        vTaskDelete(NULL);
        return;
    }
    int uno = 1;
    lwip_setsockopt(s, SOL_SOCKET, SO_BROADCAST, &uno, sizeof(uno));
    lwip_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &uno, sizeof(uno));
    struct timeval tv = {.tv_sec = 0, .tv_usec = RECV_TIMEOUT_MS * 1000};
    lwip_setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = lwip_htons(67);
    addr.sin_addr.s_addr = 0; /* INADDR_ANY: recibe broadcasts a :67 */
    if (lwip_bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind(:67) falló (¿otro DHCP?); servidor no arranca");
        lwip_close(s);
        s_task = NULL;
        vTaskDelete(NULL);
        return;
    }
    s_sock = s;
    ESP_LOGI(TAG, "servidor DHCP activo en :67 (pool %u..%u)",
             (unsigned)s_pool.start, (unsigned)s_pool.end);

    while (s_run) {
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        ssize_t n = lwip_recvfrom(s, s_rx, sizeof(s_rx), 0,
                                  (struct sockaddr *)&src, &sl);
        dhcp_lease_expire(&s_leases, now_s()); /* mantenimiento periódico */
        if (n <= 0) {
            continue; /* timeout: vuelve a comprobar s_run */
        }
        dhcp_request_t req;
        if (dhcp_parse(s_rx, (size_t)n, &req)) {
            procesar(&req);
        }
    }
    lwip_close(s);
    s_sock = -1;
    s_task = NULL;
    ESP_LOGI(TAG, "servidor DHCP detenido");
    vTaskDelete(NULL);
}

/* --- API pública --- */

void net_dhcp_stop(void)
{
    if (s_task == NULL) {
        return;
    }
    s_run = false;
    /* la tarea sale en ≤ RECV_TIMEOUT_MS y limpia s_task */
    for (int i = 0; i < 20 && s_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    s_enabled = false;
}

bool net_dhcp_start(void)
{
    net_dhcp_stop(); /* reload: para lo que hubiera */

    bool en;
    uint32_t ps, pe, lt;
    config_get_dhcp(&en, &ps, &pe, &lt);
    if (!en) {
        s_enabled = false;
        return true; /* desactivado: nada que arrancar (P-X) */
    }

    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if (sta == NULL || esp_netif_get_ip_info(sta, &info) != ESP_OK ||
        info.ip.addr == 0) {
        ESP_LOGW(TAG, "sin IP en la STA: no se puede auto-derivar el DHCP");
        return false;
    }
    uint32_t own = lwip_ntohl(info.ip.addr);
    uint32_t gw = lwip_ntohl(info.gw.addr);
    uint32_t mask = lwip_ntohl(info.netmask.addr);
    uint32_t red = own & mask;
    uint32_t bcast = red | ~mask;

    if (ps == 0 || pe == 0) {
        /* pool por defecto: .100..(.200), acotado a [red+1, bcast-1] */
        ps = red + 100;
        pe = red + 200;
    }
    if (ps <= red) ps = red + 1;
    if (pe >= bcast) pe = bcast - 1;
    if (ps > pe) { ps = red + 1; pe = bcast - 1; }

    s_pool.start = ps;
    s_pool.end = pe;
    s_pool.mask = mask;
    s_pool.gateway = gw;
    s_pool.dns = own; /* ESPHole como DNS: el objetivo de la feature */
    s_pool.own_ip = own;
    s_pool.lease_time = (lt != 0) ? lt : DHCP_DEFAULT_LEASE_S;
    dhcp_leases_init(&s_leases);
    s_netif = netif_get_by_index((u8_t)esp_netif_get_netif_impl_index(sta));

    s_enabled = true;
    s_run = true;
    if (xTaskCreate(tarea_dhcp, "net_dhcp", 4096, NULL, 5, &s_task) != pdPASS) {
        s_run = false;
        s_enabled = false;
        return false;
    }
    return true;
}

void net_dhcp_status(net_dhcp_status_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->enabled = s_enabled;
    out->pool_start = s_pool.start;
    out->pool_end = s_pool.end;
    out->mask = s_pool.mask;
    out->gateway = s_pool.gateway;
    out->dns = s_pool.dns;
    out->lease_time = s_pool.lease_time;
    if (!s_enabled) {
        return;
    }
    /* instantánea de la tabla (lectura benigna; la muta solo la tarea DHCP) */
    for (int i = 0; i < DHCP_LEASES_MAX && out->count < DHCP_LEASES_MAX; i++) {
        if (s_leases.v[i].estado == LEASE_OFFERED ||
            s_leases.v[i].estado == LEASE_BOUND) {
            net_dhcp_lease_t *l = &out->leases[out->count++];
            l->ip = s_leases.v[i].ip;
            memcpy(l->mac, s_leases.v[i].mac, DHCP_MAC_LEN);
            l->expira_s = s_leases.v[i].expira;
            l->estado = (uint8_t)s_leases.v[i].estado;
            strncpy(l->hostname, s_leases.v[i].hostname, sizeof(l->hostname) - 1);
        }
    }
}
