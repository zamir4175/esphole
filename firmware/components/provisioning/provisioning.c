/*
 * provisioning — orquestación de la máquina de estados de arranque (P18).
 * Init de Wi-Fi una sola vez; luego PROVISION (portal) ↔ CONNECTING (STA con
 * fallback por 'provisioned') hasta obtener IP en STA, momento en que retorna
 * con el AP/portal ya liberados. La ruta DNS de la spec 001 arranca después.
 */
#include "provisioning.h"

#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "prov_portal.h"
#include "provision_logic.h"

static const char *TAG = "provision";

#define BOOT_RESET_MS 3000
#define CONNECT_TIMEOUT_MS 30000

static EventGroupHandle_t s_sta_ev;
#define BIT_GOT_IP BIT0
static volatile bool s_reconnect; /* reconexión automática mientras conectamos */

static void on_wifi(void *a, esp_event_base_t b, int32_t id, void *d)
{
    (void)a;
    (void)b;
    if (id == WIFI_EVENT_STA_DISCONNECTED && s_reconnect) {
        esp_wifi_connect(); /* reintento incondicional (Principio I) */
    }
}

static void on_ip(void *a, esp_event_base_t b, int32_t id, void *d)
{
    (void)a;
    (void)b;
    if (id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = d;
        ESP_LOGI(TAG, "IP obtenida: " IPSTR, IP2STR(&e->ip_info.ip));
        xEventGroupSetBits(s_sta_ev, BIT_GOT_IP);
    }
}

static void wifi_init_once(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t *sta = esp_netif_create_default_wifi_sta();
    esp_netif_set_hostname(sta, "esphole");

    wifi_init_config_t ic = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&ic));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               on_wifi, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               on_ip, NULL));
    s_sta_ev = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE)); /* servidor DNS: sin sleep */
}

/* Intenta conectar a (ssid,pass). timeout_ms=0 ⇒ espera indefinida (P-I).
 * Devuelve true al obtener IP. */
static bool connect_sta(const char *ssid, const char *pass, uint32_t timeout_ms)
{
    wifi_config_t sc = {0};
    strlcpy((char *)sc.sta.ssid, ssid, sizeof(sc.sta.ssid));
    strlcpy((char *)sc.sta.password, pass, sizeof(sc.sta.password));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sc));

    xEventGroupClearBits(s_sta_ev, BIT_GOT_IP);
    s_reconnect = true;
    ESP_LOGI(TAG, "conectando a \"%s\"…", ssid);
    esp_wifi_connect();

    TickType_t espera = (timeout_ms == 0) ? portMAX_DELAY
                                          : pdMS_TO_TICKS(timeout_ms);
    EventBits_t bits =
        xEventGroupWaitBits(s_sta_ev, BIT_GOT_IP, pdFALSE, pdTRUE, espera);
    if (bits & BIT_GOT_IP) {
        return true;
    }
    /* timeout: dejar de reconectar y desconectar antes de volver al portal */
    s_reconnect = false;
    esp_wifi_disconnect();
    ESP_LOGW(TAG, "sin conexión en %u ms", (unsigned)timeout_ms);
    return false;
}

void provisioning_run(esphole_config_t *cfg)
{
    wifi_init_once();

    bool boot_held = prov_button_held_ms(BOOT_RESET_MS);
    if (boot_held) {
        ESP_LOGW(TAG, "botón BOOT mantenido: factory reset");
        config_clear_wifi();
        config_load(cfg); /* recarga con credenciales vacías */
    }

    bool has_creds = cfg->wifi_ssid[0] != '\0';
    prov_mode_t mode =
        provision_decide_boot(has_creds, cfg->provisioned != 0, boot_held);

    for (;;) {
        if (mode == PROV_MODE_CONNECTING) {
            uint32_t to = cfg->provisioned ? 0 : CONNECT_TIMEOUT_MS;
            if (connect_sta(cfg->wifi_ssid, cfg->wifi_pass, to)) {
                if (!cfg->provisioned) {
                    config_mark_provisioned();
                    cfg->provisioned = 1;
                    ESP_LOGI(TAG, "credenciales validadas");
                }
                return; /* → RUNNING */
            }
            /* solo se llega aquí con provisioned=0 (timeout): al portal */
            mode = PROV_MODE_PROVISION;
        }

        /* PROV_MODE_PROVISION */
        portal_start();
        portal_wait_saved(); /* bloquea hasta un POST /save válido en NVS */
        portal_stop();
        config_load(cfg); /* toma las credenciales recién guardadas */
        mode = PROV_MODE_CONNECTING;
    }
}
