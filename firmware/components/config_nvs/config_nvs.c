#include "config_nvs.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "sdkconfig.h"

static const char *TAG = "config";
#define NS "esphole"

static const ip_addr16_t CF4 = {.family = ESPHOLE_AF_V4, .bytes = {1, 1, 1, 1}};
static const ip_addr16_t Q94 = {.family = ESPHOLE_AF_V4, .bytes = {9, 9, 9, 9}};
/* 2606:4700:4700::1111 */
static const ip_addr16_t CF6 = {.family = ESPHOLE_AF_V6,
                                .bytes = {0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0x11, 0x11}};
/* 2620:fe::fe */
static const ip_addr16_t Q96 = {.family = ESPHOLE_AF_V6,
                                .bytes = {0x26, 0x20, 0x00, 0xfe, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0x00, 0xfe}};

void config_defaults(esphole_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    /* v4 primero (siempre disponibles), después v6 (C3) */
    cfg->upstream_addr[0] = CF4;
    cfg->upstream_addr[1] = Q94;
    cfg->upstream_addr[2] = CF6;
    cfg->upstream_addr[3] = Q96;
    for (int i = 0; i < CONFIG_UPSTREAMS_MAX; i++) {
        cfg->upstream_port[i] = 53;
    }
    cfg->upstream_count = 4;
    cfg->udp_payload = 1232;
    cfg->block_ttl = 30;
    cfg->cache_cap = 2048;
    cfg->ttl_cap = 3600;
    cfg->rl_ip_rate = 50;
    cfg->rl_ip_burst = 100;
    cfg->rl_glob_rate = 500;
    cfg->rl_glob_burst = 1000;
}

static void lee_u16(nvs_handle_t h, const char *clave, uint16_t *destino)
{
    uint16_t v;
    if (nvs_get_u16(h, clave, &v) == ESP_OK) {
        *destino = v;
    }
}

void config_load(esphole_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    config_defaults(cfg);

    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) {
        ESP_LOGI(TAG, "sin namespace NVS: defectos compilados");
        return;
    }
    uint8_t ver = 0;
    if (nvs_get_u8(h, "cfg_ver", &ver) != ESP_OK || ver != ESPHOLE_CFG_VERSION) {
        ESP_LOGW(TAG, "cfg_ver ausente o distinta (%u): defectos compilados", ver);
        nvs_close(h);
        return;
    }
    /* upstreams como blob {addr,port}×count; ilegible ⇒ quedan los defectos */
    struct {
        ip_addr16_t addr[CONFIG_UPSTREAMS_MAX];
        uint16_t port[CONFIG_UPSTREAMS_MAX];
        uint8_t count;
    } up;
    size_t len = sizeof(up);
    if (nvs_get_blob(h, "upstreams", &up, &len) == ESP_OK && len == sizeof(up) &&
        up.count >= 1 && up.count <= CONFIG_UPSTREAMS_MAX) {
        memcpy(cfg->upstream_addr, up.addr, sizeof(up.addr));
        memcpy(cfg->upstream_port, up.port, sizeof(up.port));
        cfg->upstream_count = up.count;
    }
    lee_u16(h, "udp_payload", &cfg->udp_payload);
    lee_u16(h, "block_ttl", &cfg->block_ttl);
    lee_u16(h, "cache_cap", &cfg->cache_cap);
    uint32_t v32;
    if (nvs_get_u32(h, "ttl_cap", &v32) == ESP_OK) {
        cfg->ttl_cap = v32;
    }
    lee_u16(h, "rl_ip_rate", &cfg->rl_ip_rate);
    lee_u16(h, "rl_ip_burst", &cfg->rl_ip_burst);
    lee_u16(h, "rl_glob_rate", &cfg->rl_glob_rate);
    lee_u16(h, "rl_glob_burst", &cfg->rl_glob_burst);

    /* Credenciales de aprovisionamiento (spec 002); ausentes ⇒ ssid vacío ya
     * fijado por config_defaults ⇒ arranque en modo AP. */
    size_t sl = sizeof(cfg->wifi_ssid);
    if (nvs_get_str(h, "wifi_ssid", cfg->wifi_ssid, &sl) != ESP_OK) {
        cfg->wifi_ssid[0] = '\0';
    }
    size_t pl = sizeof(cfg->wifi_pass);
    if (nvs_get_str(h, "wifi_pass", cfg->wifi_pass, &pl) != ESP_OK) {
        cfg->wifi_pass[0] = '\0';
    }
    uint8_t prov = 0;
    nvs_get_u8(h, "provisioned", &prov);
    cfg->provisioned = prov;

    nvs_close(h);
    ESP_LOGI(TAG, "configuración cargada de NVS (v%u)", ver);
}

bool config_save(const esphole_config_t *cfg)
{
    if (cfg == NULL) {
        return false;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    struct {
        ip_addr16_t addr[CONFIG_UPSTREAMS_MAX];
        uint16_t port[CONFIG_UPSTREAMS_MAX];
        uint8_t count;
    } up;
    memcpy(up.addr, cfg->upstream_addr, sizeof(up.addr));
    memcpy(up.port, cfg->upstream_port, sizeof(up.port));
    up.count = cfg->upstream_count;

    bool ok = nvs_set_blob(h, "upstreams", &up, sizeof(up)) == ESP_OK &&
              nvs_set_u16(h, "udp_payload", cfg->udp_payload) == ESP_OK &&
              nvs_set_u16(h, "block_ttl", cfg->block_ttl) == ESP_OK &&
              nvs_set_u16(h, "cache_cap", cfg->cache_cap) == ESP_OK &&
              nvs_set_u32(h, "ttl_cap", cfg->ttl_cap) == ESP_OK &&
              nvs_set_u16(h, "rl_ip_rate", cfg->rl_ip_rate) == ESP_OK &&
              nvs_set_u16(h, "rl_ip_burst", cfg->rl_ip_burst) == ESP_OK &&
              nvs_set_u16(h, "rl_glob_rate", cfg->rl_glob_rate) == ESP_OK &&
              nvs_set_u16(h, "rl_glob_burst", cfg->rl_glob_burst) == ESP_OK &&
              /* cfg_ver al final: hasta que no está, la carga usa defectos */
              nvs_set_u8(h, "cfg_ver", ESPHOLE_CFG_VERSION) == ESP_OK &&
              nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

bool config_save_wifi(const char *ssid, const char *pass)
{
    if (ssid == NULL || pass == NULL) {
        return false;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    /* Orden atómico (C1): provisioned=0 y las credenciales; la marca de validez
     * solo la sube config_mark_provisioned tras conectar. Un corte aquí deja
     * provisioned=0 ⇒ el arranque intenta STA y, si falla, vuelve al portal. */
    bool ok = nvs_set_u8(h, "provisioned", 0) == ESP_OK &&
              nvs_set_str(h, "wifi_ssid", ssid) == ESP_OK &&
              nvs_set_str(h, "wifi_pass", pass) == ESP_OK &&
              nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

bool config_mark_provisioned(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    bool ok = nvs_set_u8(h, "provisioned", 1) == ESP_OK &&
              nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

bool config_clear_wifi(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    /* borra la marca primero: si el borrado se interrumpe, ya no está
     * "provisionado" y el arranque vuelve al portal de todos modos */
    nvs_set_u8(h, "provisioned", 0);
    nvs_erase_key(h, "wifi_ssid"); /* ESP_ERR_NVS_NOT_FOUND es aceptable */
    nvs_erase_key(h, "wifi_pass");
    /* factory reset total: la credencial de admin también se va (FR-010) */
    nvs_erase_key(h, "adm_hash");
    nvs_erase_key(h, "adm_salt");
    bool ok = nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

bool config_set_admin(const uint8_t h32[32], const uint8_t salt[16])
{
    if (h32 == NULL || salt == NULL) {
        return false;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    /* hash y salt en la misma transacción; commit único al final ⇒ un corte deja
     * la credencial anterior (o ninguna) intacta, nunca una a medias. */
    bool ok = nvs_set_blob(h, "adm_hash", h32, 32) == ESP_OK &&
              nvs_set_blob(h, "adm_salt", salt, 16) == ESP_OK &&
              nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

bool config_get_admin(uint8_t h32[32], uint8_t salt[16])
{
    if (h32 == NULL || salt == NULL) {
        return false;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    size_t hl = 32, sl = 16;
    bool ok = nvs_get_blob(h, "adm_hash", h32, &hl) == ESP_OK && hl == 32 &&
              nvs_get_blob(h, "adm_salt", salt, &sl) == ESP_OK && sl == 16;
    nvs_close(h);
    return ok;
}

bool config_clear_admin(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    nvs_erase_key(h, "adm_hash"); /* ESP_ERR_NVS_NOT_FOUND es aceptable */
    nvs_erase_key(h, "adm_salt");
    bool ok = nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

void config_get_blocklist_url(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        size_t l = cap;
        esp_err_t e = nvs_get_str(h, "bl_url", out, &l);
        nvs_close(h);
        if (e == ESP_OK) {
            return; /* URL configurada por el usuario */
        }
    }
    strlcpy(out, CONFIG_ESPHOLE_BLOCKLIST_URL, cap); /* default compilado */
}

bool config_set_blocklist_url(const char *url)
{
    if (url == NULL || strlen(url) > BL_URL_MAX) {
        return false;
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    bool ok = nvs_set_str(h, "bl_url", url) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

void config_get_dhcp(bool *enabled, uint32_t *pool_start, uint32_t *pool_end,
                     uint32_t *lease_time)
{
    if (enabled != NULL) *enabled = false;
    if (pool_start != NULL) *pool_start = 0;
    if (pool_end != NULL) *pool_end = 0;
    if (lease_time != NULL) *lease_time = 0;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) {
        return; /* sin config ⇒ defectos (off / auto-derivar) */
    }
    uint8_t en = 0;
    if (enabled != NULL && nvs_get_u8(h, "dhcp_en", &en) == ESP_OK) {
        *enabled = (en != 0);
    }
    if (pool_start != NULL) nvs_get_u32(h, "dhcp_ps", pool_start);
    if (pool_end != NULL) nvs_get_u32(h, "dhcp_pe", pool_end);
    if (lease_time != NULL) nvs_get_u32(h, "dhcp_lt", lease_time);
    nvs_close(h);
}

bool config_set_dhcp(bool enabled, uint32_t pool_start, uint32_t pool_end,
                     uint32_t lease_time)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    bool ok = nvs_set_u8(h, "dhcp_en", enabled ? 1 : 0) == ESP_OK &&
              nvs_set_u32(h, "dhcp_ps", pool_start) == ESP_OK &&
              nvs_set_u32(h, "dhcp_pe", pool_end) == ESP_OK &&
              nvs_set_u32(h, "dhcp_lt", lease_time) == ESP_OK &&
              nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

/* SNI por defecto, alineados con los IPs de upstream por defecto (Cloudflare/Quad9). */
static const char *const DOT_SNI_DEFAULT[CONFIG_UPSTREAMS_MAX] = {
    "one.one.one.one", /* 1.1.1.1 */
    "dns.quad9.net",   /* 9.9.9.9 */
    "one.one.one.one", /* 2606:4700:4700::1111 */
    "dns.quad9.net",   /* 2620:fe::fe */
};

void config_get_dot(bool *enabled, char sni[][DOT_SNI_MAX])
{
    if (enabled != NULL) {
        *enabled = false;
    }
    if (sni != NULL) {
        for (int i = 0; i < CONFIG_UPSTREAMS_MAX; i++) {
            strlcpy(sni[i], DOT_SNI_DEFAULT[i], DOT_SNI_MAX); /* default compilado */
        }
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) != ESP_OK) {
        return; /* sin config ⇒ off / SNI por defecto */
    }
    uint8_t en = 0;
    if (enabled != NULL && nvs_get_u8(h, "dot_en", &en) == ESP_OK) {
        *enabled = (en != 0);
    }
    if (sni != NULL) {
        char blob[CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX];
        size_t len = sizeof(blob);
        if (nvs_get_blob(h, "dot_sni", blob, &len) == ESP_OK && len == sizeof(blob)) {
            for (int i = 0; i < CONFIG_UPSTREAMS_MAX; i++) {
                blob[i][DOT_SNI_MAX - 1] = '\0'; /* fuerza NUL: dato de NVS hostil */
                strlcpy(sni[i], blob[i], DOT_SNI_MAX);
            }
        }
    }
    nvs_close(h);
}

bool config_set_dot(bool enabled, const char sni[][DOT_SNI_MAX])
{
    if (sni == NULL) {
        return false;
    }
    char blob[CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX];
    memset(blob, 0, sizeof(blob));
    for (int i = 0; i < CONFIG_UPSTREAMS_MAX; i++) {
        if (strlen(sni[i]) >= DOT_SNI_MAX) {
            return false; /* no cabe con su NUL */
        }
        strlcpy(blob[i], sni[i], DOT_SNI_MAX);
    }
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) {
        return false;
    }
    bool ok = nvs_set_u8(h, "dot_en", enabled ? 1 : 0) == ESP_OK &&
              nvs_set_blob(h, "dot_sni", blob, sizeof(blob)) == ESP_OK &&
              nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}
