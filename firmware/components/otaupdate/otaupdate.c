/*
 * otaupdate — implementación. Ver otaupdate.h.
 * O02 cubre el ciclo de arranque (confirmación / vuelta atrás). La descarga
 * (esp_https_ota) y el estado observable llegan en O03.
 */
#include "otaupdate.h"

#include <string.h>

#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "otaupd";

#define OTA_VALIDATE_TIMEOUT_MS 120000 /* gracia para confirmar tras una OTA */
#define OTA_TIMEOUT_MS 60000           /* timeout de la descarga (imagen grande) */
#define OTA_TASK_STACK 8192
#define OTA_URL_MAX 200

static otaupdate_status_t s_st;
static char s_url[OTA_URL_MAX + 1];

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

static esp_timer_handle_t s_validate_timer;

static void validate_timeout_cb(void *arg)
{
    (void)arg;
    /* el arranque a prueba no se confirmó: reiniciar ⇒ el bootloader revierte */
    ESP_LOGE(TAG, "arranque a prueba no confirmado en %d s: reiniciando (rollback)",
             OTA_VALIDATE_TIMEOUT_MS / 1000);
    esp_restart();
}

void otaupdate_boot_check(void)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    esp_ota_img_states_t st;
    if (run != NULL && esp_ota_get_state_partition(run, &st) == ESP_OK &&
        st == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGW(TAG,
                 "arranque A PRUEBA (ranura %s): se revertirá si no se confirma en %d s",
                 run->label, OTA_VALIDATE_TIMEOUT_MS / 1000);
        const esp_timer_create_args_t args = {.callback = validate_timeout_cb,
                                               .name = "ota_validate"};
        if (esp_timer_create(&args, &s_validate_timer) == ESP_OK) {
            esp_timer_start_once(s_validate_timer,
                                 (uint64_t)OTA_VALIDATE_TIMEOUT_MS * 1000);
        }
#if CONFIG_ESPHOLE_OTA_SELFTEST_PANIC
        /* imagen de autotest del rollback (OB-08): aborta a propósito en el
         * arranque a prueba ⇒ el bootloader revierte a la versión anterior. */
        ESP_LOGE(TAG, "AUTOTEST: abortando el arranque a prueba para forzar rollback");
        abort();
#endif
    } else {
        ESP_LOGI(TAG, "arranque normal (ranura %s)", run != NULL ? run->label : "?");
    }
}

void otaupdate_confirm_healthy(void)
{
    if (s_validate_timer != NULL) {
        esp_timer_stop(s_validate_timer);
        esp_timer_delete(s_validate_timer);
        s_validate_timer = NULL;
    }
    const esp_partition_t *run = esp_ota_get_running_partition();
    /* marca la ranura en ejecución como válida: confirma tras una OTA y, en un
     * arranque normal, deja el slot en estado VALID (para que un rollback futuro
     * tenga una imagen buena a la que volver). */
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    ESP_LOGI(TAG, "firmware confirmado, ranura %s (%s)",
             run != NULL ? run->label : "?",
             e == ESP_OK ? "válido" : esp_err_to_name(e));
}

/* --- descarga OTA (O03) --- */

void otaupdate_running_version(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return;
    }
    const esp_app_desc_t *d = esp_app_get_description();
    strlcpy(out, (d != NULL) ? d->version : "?", cap);
}

void otaupdate_running_slot(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return;
    }
    const esp_partition_t *run = esp_ota_get_running_partition();
    strlcpy(out, (run != NULL) ? run->label : "?", cap);
}

static void set_error(const char *msg)
{
    s_st.estado = OTA_ERROR;
    strlcpy(s_st.error, msg, sizeof(s_st.error));
}

static void tarea_ota(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "OTA desde %s", s_url);
    s_st.estado = OTA_DOWNLOADING;
    s_st.leido = 0;
    s_st.total = 0;

    esp_http_client_config_t http = {
        .url = s_url,
        .crt_bundle_attach = esp_crt_bundle_attach, /* valida cadena de CAs */
        .timeout_ms = OTA_TIMEOUT_MS,
        .keep_alive_enable = false,
    };
    esp_https_ota_config_t cfg = {.http_config = &http};
    esp_https_ota_handle_t h = NULL;

    esp_err_t err = esp_https_ota_begin(&cfg, &h);
    if (err != ESP_OK) {
        set_error("no se pudo iniciar (URL/TLS)");
        goto fin;
    }
    s_st.total = (uint32_t)esp_https_ota_get_image_size(h);

    while (1) {
        err = esp_https_ota_perform(h);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            break;
        }
        s_st.leido = (uint32_t)esp_https_ota_get_image_len_read(h);
    }
    if (err != ESP_OK) {
        set_error("descarga/escritura falló");
        goto fin_abort;
    }
    if (!esp_https_ota_is_complete_data_received(h)) {
        set_error("imagen incompleta");
        goto fin_abort;
    }
    err = esp_https_ota_finish(h); /* valida la imagen y fija el arranque; consume h */
    h = NULL;
    if (err != ESP_OK) {
        set_error(err == ESP_ERR_OTA_VALIDATE_FAILED ? "imagen inválida"
                                                      : "no se pudo finalizar");
        goto fin;
    }

    /* éxito: la ranura nueva arrancará a prueba (O02 la confirmará) */
    s_st.estado = OTA_DONE;
    s_st.leido = s_st.total;
    s_st.cuando_s = now_s();
    s_st.en_curso = false;
    ESP_LOGW(TAG, "OTA completada: reiniciando en la ranura nueva");
    vTaskDelay(pdMS_TO_TICKS(500)); /* deja salir la respuesta HTTP */
    esp_restart();
    return; /* inalcanzable */

fin_abort:
    if (h != NULL) {
        esp_https_ota_abort(h);
    }
fin:
    ESP_LOGE(TAG, "OTA fallida: %s (firmware actual intacto)", s_st.error);
    s_st.cuando_s = now_s();
    s_st.en_curso = false;
    vTaskDelete(NULL);
}

/* El firmware DEBE llegar por un canal autenticado: sin firma de imagen, un HTTP
 * en claro permitiría inyectar firmware arbitrario (P-V). Solo https, salvo el
 * opt-in de desarrollo CONFIG_ESPHOLE_OTA_ALLOW_INSECURE_HTTP (LAN de confianza). */
static bool esquema_valido(const char *url)
{
    if (strncmp(url, "https://", 8) == 0) {
        return true;
    }
#if CONFIG_ESPHOLE_OTA_ALLOW_INSECURE_HTTP
    if (strncmp(url, "http://", 7) == 0) {
        return true;
    }
#endif
    return false;
}

bool otaupdate_trigger(const char *url)
{
    if (url == NULL || !esquema_valido(url) || strlen(url) > OTA_URL_MAX) {
        return false;
    }
    if (s_st.en_curso) {
        return false; /* una a la vez (FR-010) */
    }
    s_st.en_curso = true;
    s_st.error[0] = '\0';
    strlcpy(s_url, url, sizeof(s_url));
    if (xTaskCreate(tarea_ota, "otaupd", OTA_TASK_STACK, NULL, 4, NULL) != pdPASS) {
        s_st.en_curso = false;
        return false;
    }
    return true;
}

void otaupdate_status(otaupdate_status_t *out)
{
    if (out != NULL) {
        *out = s_st;
    }
}
