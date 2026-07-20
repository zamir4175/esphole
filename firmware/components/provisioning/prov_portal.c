/*
 * prov_portal — modo AP + portal cautivo (P13–P17).
 * APSTA para servir el portal y escanear a la vez; AP con identidad única
 * derivada del MAC; DHCP opción 114; DNS cautivo con dns_wire; esp_http_server
 * con página de configuración, endpoints de sondeo (302→/) y POST /save que
 * valida con provision_logic y persiste en NVS. Al recibir credenciales
 * válidas señaliza a la orquestación.
 */
#include "prov_portal.h"

#include <string.h>

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"

#include "config_nvs.h"
#include "dns_wire.h"
#include "provision_logic.h"

static const char *TAG = "portal";

#define AP_CHANNEL 1
#define AP_MAX_CONN 4
#define SCAN_MAX 12          /* redes mostradas en el portal */
#define DNS_TASK_STACK 3072

static const uint8_t AP_IP[4] = {192, 168, 4, 1};

static EventGroupHandle_t s_ev;
#define BIT_SAVED BIT0
static httpd_handle_t s_http;
static esp_netif_t *s_ap_netif;
static int s_dns_sock = -1;
static TaskHandle_t s_dns_task;
static volatile bool s_dns_run;

/* --- página del portal (HTML+JS mínimo, servido estático) --- */
static const char PAGE[] =
    "<!doctype html><html><head><meta name=viewport "
    "content='width=device-width,initial-scale=1'><title>ESPHole</title>"
    "<style>body{font-family:sans-serif;max-width:26em;margin:2em auto;padding:0 1em}"
    "select,input,button{width:100%;padding:.6em;margin:.3em 0;font-size:1em}"
    "button{background:#2a6;color:#fff;border:0;border-radius:4px}</style></head>"
    "<body><h2>ESPHole &mdash; configurar Wi-Fi</h2>"
    "<form method=POST action=/save>"
    "<label>Red</label><select name=ssid id=s><option>escaneando&hellip;</option></select>"
    "<label>Contrase&ntilde;a</label><input name=pass type=password autocomplete=off>"
    "<button type=submit>Guardar y conectar</button></form>"
    "<script>fetch('/scan').then(r=>r.json()).then(l=>{var s=document.getElementById('s');"
    "s.innerHTML='';l.forEach(function(n){var o=document.createElement('option');"
    "o.value=n.ssid;o.textContent=n.ssid+' ('+n.rssi+' dBm)';s.appendChild(o);});"
    "if(!l.length)s.innerHTML='<option>(ninguna red encontrada)</option>';});</script>"
    "</body></html>";

static const char PAGE_OK[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<body style='font-family:sans-serif;max-width:26em;margin:2em auto'>"
    "<h2>Credenciales guardadas</h2><p>El ESPHole se est&aacute; conectando a tu red. "
    "Si los datos eran correctos, en unos segundos dejar&aacute; de emitir esta red y "
    "empezar&aacute; a funcionar. Si no, volver&aacute; a mostrar este portal.</p></body>";

static const char PAGE_ERR[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<body style='font-family:sans-serif;max-width:26em;margin:2em auto'>"
    "<h2>Datos no v&aacute;lidos</h2><p>Revisa el nombre de red y la contrase&ntilde;a "
    "(8&ndash;63 caracteres, o vac&iacute;a para red abierta).</p>"
    "<p><a href=/>Volver</a></p></body>";

/* --- handlers HTTP --- */

static esp_err_t h_root(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, PAGE, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t h_scan(httpd_req_t *req)
{
    uint16_t n = 0;
    wifi_scan_config_t sc = {.show_hidden = false};
    esp_wifi_scan_start(&sc, true); /* bloqueante corto */
    esp_wifi_scan_get_ap_num(&n);
    if (n > SCAN_MAX) {
        n = SCAN_MAX;
    }
    wifi_ap_record_t recs[SCAN_MAX];
    esp_wifi_scan_get_ap_records(&n, recs);

    char buf[SCAN_MAX * 80 + 4];
    size_t w = 0;
    buf[w++] = '[';
    for (uint16_t i = 0; i < n; i++) {
        /* filtra SSID vacíos (redes ocultas) */
        if (recs[i].ssid[0] == '\0') {
            continue;
        }
        w += (size_t)snprintf(buf + w, sizeof(buf) - w,
                              "%s{\"ssid\":\"%s\",\"rssi\":%d}",
                              (w > 1) ? "," : "", (char *)recs[i].ssid,
                              recs[i].rssi);
        if (w >= sizeof(buf) - 82) {
            break;
        }
    }
    buf[w++] = ']';
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, w);
}

static esp_err_t h_save(httpd_req_t *req)
{
    char body[256];
    int total = 0;
    while (total < (int)sizeof(body) - 1) {
        int r = httpd_req_recv(req, body + total, sizeof(body) - 1 - total);
        if (r <= 0) {
            break;
        }
        total += r;
    }
    body[total > 0 ? total : 0] = '\0';

    prov_creds_t creds;
    if (provision_form_parse(body, (size_t)total, &creds) != PROV_FORM_OK ||
        !provision_creds_valid(&creds)) {
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, PAGE_ERR, HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    if (!config_save_wifi(creds.ssid, creds.pass)) {
        httpd_resp_send_500(req);
        return ESP_OK;
    }
    ESP_LOGI(TAG, "credenciales guardadas para \"%s\"", creds.ssid);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, PAGE_OK, HTTPD_RESP_USE_STRLEN);
    xEventGroupSetBits(s_ev, BIT_SAVED); /* despierta a la orquestación */
    return ESP_OK;
}

/* sondas de portal cautivo (iOS/Android/Windows) y 404 → 302 a la raíz */
static esp_err_t redir_root(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    /* iOS exige cuerpo no vacío para detectar el portal */
    httpd_resp_send(req, "captive", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t err_404(httpd_req_t *req, httpd_err_code_t e)
{
    (void)e;
    return redir_root(req);
}

/* --- DNS cautivo: responde AP_IP a toda consulta A (P14) --- */

static void dns_task(void *arg)
{
    (void)arg;
    uint8_t rx[512];
    uint8_t tx[540];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    while (s_dns_run) {
        int n = recvfrom(s_dns_sock, rx, sizeof(rx), 0,
                         (struct sockaddr *)&from, &flen);
        if (n < 12) {
            continue;
        }
        dns_query_t q;
        if (dns_wire_parse_query(rx, (size_t)n, &q) != DNS_WIRE_OK) {
            continue;
        }
        size_t m = dns_wire_build_a_response(&q, AP_IP, 5, tx, sizeof(tx));
        if (m > 0) {
            sendto(s_dns_sock, tx, m, 0, (struct sockaddr *)&from, flen);
        }
    }
    close(s_dns_sock);
    s_dns_sock = -1;
    vTaskDelete(NULL);
}

static void dns_start(void)
{
    s_dns_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s_dns_sock < 0) {
        return;
    }
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_addr.s_addr = htonl(INADDR_ANY),
                            .sin_port = htons(53)};
    if (bind(s_dns_sock, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(s_dns_sock);
        s_dns_sock = -1;
        return;
    }
    s_dns_run = true;
    xTaskCreate(dns_task, "captive_dns", DNS_TASK_STACK, NULL, 5, &s_dns_task);
}

/* --- ciclo de vida del portal --- */

void portal_start(void)
{
    s_ev = xEventGroupCreate();

    s_ap_netif = esp_netif_create_default_wifi_ap();
    /* opción DHCP 114: URL del portal (RFC 8910) */
    char uri[] = "http://192.168.4.1";
    esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET,
                           ESP_NETIF_CAPTIVEPORTAL_URI, uri, strlen(uri));

    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    char ssid[16], pass[16];
    provision_ap_ssid(mac, ssid);
    /* clave WPA2 desde el RNG por hardware (Wi-Fi activo ⇒ RNG verdadero):
     * un secreto real, no derivable del MAC público (Principio V) */
    uint8_t rb[8];
    esp_fill_random(rb, sizeof(rb));
    provision_ap_pass(rb, pass);
    ESP_LOGW(TAG, "=== MODO APROVISIONAMIENTO ===");
    ESP_LOGW(TAG, "  red:  %s", ssid);
    ESP_LOGW(TAG, "  clave: %s", pass);
    ESP_LOGW(TAG, "  luego abre http://192.168.4.1/");

    wifi_config_t apc = {0};
    strlcpy((char *)apc.ap.ssid, ssid, sizeof(apc.ap.ssid));
    apc.ap.ssid_len = strlen(ssid);
    strlcpy((char *)apc.ap.password, pass, sizeof(apc.ap.password));
    apc.ap.channel = AP_CHANNEL;
    apc.ap.max_connection = AP_MAX_CONN;
    apc.ap.authmode = WIFI_AUTH_WPA2_PSK;

    /* wifi ya está inicializado y arrancado por provisioning_run; aquí solo se
     * conmuta a APSTA (STA para escanear) y se configura el AP */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &apc));

    httpd_config_t hc = HTTPD_DEFAULT_CONFIG();
    hc.max_uri_handlers = 10;
    hc.lru_purge_enable = true;
    ESP_ERROR_CHECK(httpd_start(&s_http, &hc));
    const httpd_uri_t rutas[] = {
        {.uri = "/", .method = HTTP_GET, .handler = h_root},
        {.uri = "/scan", .method = HTTP_GET, .handler = h_scan},
        {.uri = "/save", .method = HTTP_POST, .handler = h_save},
        {.uri = "/generate_204", .method = HTTP_GET, .handler = redir_root},
        {.uri = "/gen_204", .method = HTTP_GET, .handler = redir_root},
        {.uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = redir_root},
        {.uri = "/ncsi.txt", .method = HTTP_GET, .handler = redir_root},
        {.uri = "/connecttest.txt", .method = HTTP_GET, .handler = redir_root},
    };
    for (size_t i = 0; i < sizeof(rutas) / sizeof(rutas[0]); i++) {
        httpd_register_uri_handler(s_http, &rutas[i]);
    }
    httpd_register_err_handler(s_http, HTTPD_404_NOT_FOUND, err_404);

    dns_start();
    ESP_LOGI(TAG, "portal activo en http://192.168.4.1/");
}

bool portal_wait_saved(void)
{
    xEventGroupWaitBits(s_ev, BIT_SAVED, pdTRUE, pdFALSE, portMAX_DELAY);
    return true;
}

void portal_stop(void)
{
    s_dns_run = false;
    if (s_http != NULL) {
        httpd_stop(s_http);
        s_http = NULL;
    }
    /* da un instante a la tarea DNS para cerrar su socket y salir */
    vTaskDelay(pdMS_TO_TICKS(100));
    if (s_ap_netif != NULL) {
        esp_wifi_set_mode(WIFI_MODE_STA); /* baja el AP */
        esp_netif_destroy_default_wifi(s_ap_netif);
        s_ap_netif = NULL;
    }
    if (s_ev != NULL) {
        vEventGroupDelete(s_ev);
        s_ev = NULL;
    }
    ESP_LOGI(TAG, "portal detenido; recursos liberados");
}
