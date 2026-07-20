/*
 * listupdate — implementación. Ver listupdate.h.
 * Ruta feliz: suspend(EMPTY) → reset → descarga+parseo+add → finalize(ACTIVE)
 * → persist. Ruta de fallo: recarga la lista previa desde la partición.
 */
#include "listupdate.h"

#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "blocklist_load.h"
#include "config_nvs.h"
#include "domain.h"
#include "hostlist.h"
#include "net_dns.h"

static const char *TAG = "listupd";

#define CHUNK 1024
#define LU_LINE_MAX 300
#define DOWNLOAD_TIMEOUT_MS 30000
#define DOWNLOAD_MAX_BYTES (8u * 1024 * 1024)
#define TASK_STACK 8192

static blocklist_t *s_bl;
static listupdate_status_t s_st;
static char s_url[BL_URL_MAX + 1];

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

static void set_error(const char *msg)
{
    s_st.estado = LU_ERROR;
    strlcpy(s_st.error, msg, sizeof(s_st.error));
}

/* Procesa UNA línea de la lista: extrae dominio, normaliza-invierte y añade. */
static void procesa_linea(const char *line, size_t len)
{
    const char *dom;
    size_t dlen;
    if (!hostlist_parse_line(line, len, &dom, &dlen)) {
        return; /* comentario, vacía o excluido */
    }
    char inv[ESPHOLE_DOMAIN_MAX + 1];
    int n = domain_normalize_invert(dom, dlen, inv);
    if (n > 0) {
        blocklist_add(s_bl, inv, (size_t)n);
    }
}

/* Descarga la URL en streaming y alimenta cada línea a procesa_linea.
 * Devuelve true si la descarga completó bien. */
static bool descarga_y_construye(const char *url)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach, /* valida cadena de CAs */
        .timeout_ms = DOWNLOAD_TIMEOUT_MS,
        .buffer_size = CHUNK,
        .keep_alive_enable = false,
    };
    esp_http_client_handle_t cli = esp_http_client_init(&cfg);
    if (cli == NULL) {
        set_error("cliente HTTP no creado");
        return false;
    }
    bool ok = false;
    esp_err_t e = esp_http_client_open(cli, 0);
    if (e != ESP_OK) {
        set_error("no se pudo conectar");
        goto fin;
    }
    if (esp_http_client_fetch_headers(cli) < 0) {
        set_error("sin cabeceras");
        goto fin;
    }
    int status = esp_http_client_get_status_code(cli);
    if (status != 200) {
        char m[48];
        snprintf(m, sizeof(m), "HTTP %d", status);
        set_error(m);
        goto fin;
    }

    s_st.estado = LU_BUILDING;
    char chunk[CHUNK];
    char line[LU_LINE_MAX];
    size_t ll = 0;
    bool ovf = false; /* la línea actual excedió LU_LINE_MAX: se descarta */
    uint32_t total = 0;
    int r;
    while ((r = esp_http_client_read(cli, chunk, sizeof(chunk))) > 0) {
        total += (uint32_t)r;
        s_st.descargados = total;
        if (total > DOWNLOAD_MAX_BYTES) {
            set_error("descarga demasiado grande");
            goto fin;
        }
        for (int i = 0; i < r; i++) {
            char c = chunk[i];
            if (c == '\n') {
                if (!ovf) {
                    procesa_linea(line, ll);
                }
                ll = 0;
                ovf = false;
            } else if (ll < LU_LINE_MAX) {
                line[ll++] = c;
            } else {
                ovf = true; /* línea sobre-larga: ignorar hasta el próximo \n */
            }
        }
    }
    if (r < 0) {
        set_error("error de lectura");
        goto fin;
    }
    if (ll > 0 && !ovf) {
        procesa_linea(line, ll); /* última línea sin \n final */
    }
    ok = true;

fin:
    esp_http_client_close(cli);
    esp_http_client_cleanup(cli);
    return ok;
}

static void tarea_update(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "actualizando lista desde %s", s_url);

    /* fail-open: el bloqueo queda inactivo durante la reconstrucción */
    s_st.estado = LU_DOWNLOADING;
    s_st.descargados = 0;
    net_dns_blocklist_suspend();
    blocklist_reset(s_bl);

    if (descarga_y_construye(s_url)) {
        blocklist_finalize(s_bl); /* ordena+dedup, restaura BL_ACTIVE */
        s_st.estado = LU_WRITING;
        if (blocklist_save_to_partition(s_bl)) {
            s_st.estado = LU_OK;
            s_st.count = s_bl->count;
            ESP_LOGI(TAG, "lista actualizada: %u dominios (truncados %u)",
                     (unsigned)s_bl->count, (unsigned)s_bl->truncated);
        } else {
            set_error("no se pudo persistir");
        }
    }

    if (s_st.estado == LU_ERROR) {
        /* recupera la lista previa intacta desde la partición */
        ESP_LOGW(TAG, "actualización fallida (%s): restaurando lista previa",
                 s_st.error);
        blocklist_reload_from_partition(s_bl);
        s_st.count = s_bl->count;
    }

    s_st.cuando_s = now_s();
    s_st.en_curso = false;
    vTaskDelete(NULL);
}

/* --- API pública --- */

void listupdate_start(blocklist_t *bl)
{
    s_bl = bl;
    memset(&s_st, 0, sizeof(s_st));
    s_st.estado = LU_IDLE;
    s_st.count = (bl != NULL) ? bl->count : 0;
}

static bool esquema_valido(const char *url)
{
    return strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0;
}

bool listupdate_trigger(const char *url)
{
    if (s_bl == NULL || url == NULL || !esquema_valido(url) ||
        strlen(url) > BL_URL_MAX) {
        return false;
    }
    if (s_st.en_curso) {
        return false; /* una a la vez (FR-010) */
    }
    s_st.en_curso = true; /* la tarea la baja al terminar */
    s_st.error[0] = '\0';
    strlcpy(s_url, url, sizeof(s_url));
    if (xTaskCreate(tarea_update, "listupd", TASK_STACK, NULL, 4, NULL) != pdPASS) {
        s_st.en_curso = false;
        return false;
    }
    return true;
}

void listupdate_status(listupdate_status_t *out)
{
    if (out != NULL) {
        *out = s_st;
        if (s_bl != NULL && !s_st.en_curso) {
            out->count = s_bl->count; /* refleja la lista viva */
        }
    }
}
