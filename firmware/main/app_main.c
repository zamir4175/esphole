/*
 * ESPHole — punto de entrada.
 * Orden de arranque (fail-open por construcción): NVS → configuración →
 * métricas → red → estructuras (PSRAM) → listener DNS → carga de lista.
 * El listener atiende desde antes de que la lista esté ACTIVA: mientras
 * tanto todo se reenvía (CB-20).
 */
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/def.h"
#include "nvs_flash.h"

#include "blocklist.h"
#include "bench.h"
#include "blocklist_load.h"
#include "cache.h"
#include "config_nvs.h"
#include "domain.h"
#include "esphole_types.h"
#include "metrics.h"
#include "net_dns.h"
#include "listupdate.h"
#include "net_dhcp.h"
#include "net_dot.h"
#include "otaupdate.h"
#include "policy.h"
#include "provisioning.h"
#include "upstream.h"
#include "webapi.h"

static const char *TAG = "esphole";

/* Presupuesto de PSRAM (plan.md): lista ≤6 MB (blob+índice), caché ≤1.5 MB */
#define BLOB_CAP (5u * 1024 * 1024 + 200 * 1024)
#define INDEX_CAP 200000u

static esphole_config_t s_cfg;
static policy_t s_policy;
static blocklist_t s_bl;
static cache_t s_cache;

/* Fallback si la partición no trae lista válida (desarrollo). */
static const char *LISTA_PRUEBA[] = {
    "doubleclick.net",
    "ads.tracker.net",
    "example.com",
};

static void carga_lista(void)
{
    if (blocklist_load_from_partition(&s_bl)) {
        return; /* lista real de la partición (T027) */
    }
    ESP_LOGW(TAG, "sin lista en partición: cargando lista de prueba");
    char inv[ESPHOLE_DOMAIN_MAX + 1];
    for (size_t i = 0; i < sizeof(LISTA_PRUEBA) / sizeof(LISTA_PRUEBA[0]); i++) {
        int n = domain_normalize_invert(LISTA_PRUEBA[i], strlen(LISTA_PRUEBA[i]), inv);
        if (n > 0) {
            blocklist_add(&s_bl, inv, (size_t)n);
        }
    }
    blocklist_finalize(&s_bl);
    ESP_LOGI(TAG, "lista de bloqueo ACTIVA: %u dominios (truncados %u)",
             (unsigned)s_bl.count, (unsigned)s_bl.truncated);
}

/* Subredes locales: la v4 de la interfaz activa + link-local v6 (R6). */
static void deriva_policy(void)
{
    memset(&s_policy, 0, sizeof(s_policy));
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info;
    if (netif != NULL && esp_netif_get_ip_info(netif, &info) == ESP_OK) {
        uint32_t ip = lwip_htonl(info.ip.addr);
        uint32_t mask = lwip_htonl(info.netmask.addr);
        subnet_t *s = &s_policy.subnets[s_policy.count++];
        s->base.family = ESPHOLE_AF_V4;
        uint32_t red = ip & mask;
        s->base.bytes[0] = (uint8_t)(red >> 24);
        s->base.bytes[1] = (uint8_t)(red >> 16);
        s->base.bytes[2] = (uint8_t)(red >> 8);
        s->base.bytes[3] = (uint8_t)red;
        uint8_t bits = 0;
        for (uint32_t m = mask; m & 0x80000000u; m <<= 1) {
            bits++;
        }
        s->prefix_len = bits;
        ESP_LOGI(TAG, "subred local: %u.%u.%u.%u/%u", s->base.bytes[0],
                 s->base.bytes[1], s->base.bytes[2], s->base.bytes[3], bits);
    }
    /* fe80::/10 (vecinos v6 en el enlace) */
    subnet_t *s6 = &s_policy.subnets[s_policy.count++];
    s6->base.family = ESPHOLE_AF_V6;
    s6->base.bytes[0] = 0xfe;
    s6->base.bytes[1] = 0x80;
    s6->prefix_len = 10;
}

/* Polling del botón BOOT para el factory reset en caliente (FR-010). */
static void tarea_reset_boton(void *arg)
{
    (void)arg;
    for (;;) {
        if (prov_button_held_ms(3000)) {
            ESP_LOGW(TAG, "botón BOOT mantenido en operación: factory reset");
            config_clear_wifi();
            esp_restart();
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "ESPHole arrancando (IDF %s)", esp_get_idf_version());

    /* NVS corrupta o migrada ⇒ se regenera; el arranque no se detiene (P-VIII) */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS inválida: regenerando");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }

    /* OTA (spec 005): si venimos de una actualización, este arranque es "a
     * prueba"; arma el timer de gracia para revertir si no llegamos a confirmar. */
    otaupdate_boot_check();

    config_load(&s_cfg);
    ESP_LOGI(TAG, "config: %u upstreams, payload %u, block_ttl %u, cache %u",
             s_cfg.upstream_count, s_cfg.udp_payload, s_cfg.block_ttl,
             s_cfg.cache_cap);

    metrics_init();

    /* FR-013: override de desarrollo por Kconfig — si hay SSID compilado, se usa
     * y se salta el portal (provisioned=1 ⇒ CONNECTING directo). En producción
     * está vacío y manda el aprovisionamiento por portal. */
    if (CONFIG_ESPHOLE_WIFI_SSID[0] != '\0') {
        strlcpy(s_cfg.wifi_ssid, CONFIG_ESPHOLE_WIFI_SSID, sizeof(s_cfg.wifi_ssid));
        strlcpy(s_cfg.wifi_pass, CONFIG_ESPHOLE_WIFI_PASSWORD, sizeof(s_cfg.wifi_pass));
        s_cfg.provisioned = 1;
        ESP_LOGI(TAG, "override Kconfig: conexión directa a \"%s\"", s_cfg.wifi_ssid);
    }

    /* Aprovisionamiento: bloquea hasta tener IP en STA (portal si hace falta). */
    provisioning_run(&s_cfg);
    deriva_policy();

    /* estructuras grandes en PSRAM, dentro del presupuesto del plan (P-II) */
    char *blob = heap_caps_malloc(BLOB_CAP, MALLOC_CAP_SPIRAM);
    uint32_t *indice = heap_caps_malloc(INDEX_CAP * 4, MALLOC_CAP_SPIRAM);
    void *cache_mem = heap_caps_malloc(cache_mem_size(s_cfg.cache_cap),
                                       MALLOC_CAP_SPIRAM);
    if (blob == NULL || indice == NULL || cache_mem == NULL) {
        /* sin PSRAM utilizable: seguir vivo como reenviador puro (P-I) */
        ESP_LOGE(TAG, "sin PSRAM para lista/caché: modo reenvío puro");
    }
    blocklist_init(&s_bl, blob, (blob != NULL) ? BLOB_CAP : 0, indice,
                   (indice != NULL) ? INDEX_CAP : 0);
    cache_init(&s_cache, cache_mem, (cache_mem != NULL) ? s_cfg.cache_cap : 0,
               s_cfg.ttl_cap);

    /* el listener arranca ANTES de cargar la lista: fail-open desde el
     * primer segundo (CB-20) */
    if (!net_dns_start(&s_cfg, &s_policy, &s_bl, &s_cache)) {
        ESP_LOGE(TAG, "listener DNS no arrancó; reiniciando en 5 s");
        vTaskDelay(pdMS_TO_TICKS(5000));
        esp_restart();
    }
    if (!upstream_start(&s_cfg, &s_cache)) {
        /* sin reenvío los misses responden SERVFAIL, pero bloqueo y caché
         * siguen vivos: mejor eso que reiniciar en bucle (P-I) */
        ESP_LOGE(TAG, "reenvío upstream no arrancó: solo bloqueo/caché");
    }
    if (!net_dns_tcp_start(&s_cfg, &s_policy)) {
        /* sin TCP las respuestas grandes quedan en TC sin reintento, pero
         * UDP sigue intacto: degradación, no fallo (P-I) */
        ESP_LOGE(TAG, "listener TCP no arrancó: solo UDP");
    }
#if CONFIG_ESPHOLE_BENCH
    bench_run(&s_bl); /* 200k sintéticos + mediciones de cota (T029) */
#else
    carga_lista();
#endif

    /* Actualización de la lista desde URL (spec 004): registra el handle de la
     * lista viva para poder reconstruirla en caliente. */
    listupdate_start(&s_bl);

    /* Interfaz web de administración (spec 003). Arranca DESPUÉS de la ruta DNS
     * y en su propia tarea (esp_http_server): la resolución no se degrada aunque
     * la web reciba carga (AB-11, P-I). Si no arranca, el DNS sigue igual. */
    if (!webapi_start(&s_cfg)) {
        ESP_LOGW(TAG, "interfaz web no disponible: el servicio DNS sigue activo");
    }

    /* Servidor DHCP opcional (spec 006): OFF por defecto; solo arranca si el
     * usuario lo activó desde la web (Principio X). No toca la ruta DNS. */
    net_dhcp_start();

    /* Upstream cifrado opcional (DoT, spec 007): OFF por defecto. Arranca
     * DESPUÉS de upstream_start (así guarda el forward UDP para restaurarlo);
     * si está activado, conmuta el reenvío a la tarea DoT. Con DoT off, el
     * reenvío UDP en claro queda intacto (Principio X). */
    net_dot_start();

    ESP_LOGI(TAG, "heap interno libre: %u B | PSRAM libre: %u B",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    /* Factory reset en caliente: mantener BOOT ≥3 s en operación borra las
     * credenciales y reinicia al portal (FR-010, sin la interfaz web). */
    xTaskCreate(tarea_reset_boton, "boot_reset", 2560, NULL, 3, NULL);

    /* Arranque completo y sano (Wi-Fi con IP, listeners y web arriba): confirma
     * el firmware para cancelar cualquier rollback pendiente (spec 005). */
    otaupdate_confirm_healthy();
}
