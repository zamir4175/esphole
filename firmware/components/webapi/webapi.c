/*
 * webapi — implementación. Ver webapi.h. Un solo hilo (la tarea de
 * esp_http_server atiende las peticiones en serie), por lo que las tablas de
 * sesiones y nonces de webapi_logic no necesitan cerrojos.
 */
#include "webapi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_spiffs.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/md.h"
#include "mbedtls/private/pkcs5.h"
#include "psa/crypto.h"

#include "cache.h"
#include "listupdate.h"
#include "metrics.h"
#include "net_dhcp.h"
#include "net_dns.h"
#include "net_dot.h"
#include "otaupdate.h"
#include "upstream.h"
#include "webapi_logic.h"

static const char *TAG = "webapi";

#define WWW_BASE "/spiffs"
#define COOKIE_NAME "esphole_session"
#define BODY_MAX 512      /* cuerpos de setup/login/config: acotados */
#define STATUS_JSON_MAX 1024
#define PASS_MIN 8        /* longitud mínima de la contraseña de admin */
#define PASS_MAX 64
/* Estiramiento de clave para el hash de admin (P-V). El mismo valor DEBE usarse
 * en el cliente (www/app.js) y en los guiones de prueba. El dispositivo solo lo
 * calcula una vez (en /api/setup); el cliente lo recalcula en cada login.
 * 30k ≈ 2.6 s de setup en el S3 (~11.5k it/s) y <1 s de login en el navegador.
 * Nota: 'h' es equivalente a credencial (es la clave del HMAC), así que las
 * iteraciones no protegen el login si se vuelca la NVS — solo encarecen la
 * recuperación de la contraseña EN CLARO (defensa en profundidad). */
#define WEBAPI_KDF_ITERS 30000u

/* --- estado del módulo (solo la tarea HTTP lo toca) --- */
static const esphole_config_t *s_cfg;
static httpd_handle_t s_http;
static bool s_spiffs_ok;
static webapi_sessions_t s_sessions;
static webapi_nonces_t s_nonces;

/* Anti-fuerza-bruta de login: ventana simple (FR-012). */
static uint32_t s_login_win_start;
static uint16_t s_login_fails;
#define LOGIN_WIN_S 30
#define LOGIN_MAX_FAILS 8

static uint32_t now_s(void) { return (uint32_t)(esp_timer_get_time() / 1000000); }

/* --- utilidades hex/RNG --- */

static const char HEXD[] = "0123456789abcdef";

static void to_hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = HEXD[in[i] >> 4];
        out[i * 2 + 1] = HEXD[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

/* token/nonce de 16 bytes aleatorios → 32 hex (RNG hardware). */
static void rand_hex16(char out[33])
{
    uint8_t b[16];
    esp_fill_random(b, sizeof(b));
    to_hex(b, sizeof(b), out);
}

/* --- cripto (mbedTLS), inyectable en la verificación pura --- */

/* h = PBKDF2-HMAC-SHA256(pass, salt, ITERS). El hash de admin persistido
 * (FR-002, P-V): el estiramiento de clave hace inviable recuperar la contraseña
 * en claro aunque se vuelque la NVS. out queda en ceros si algo falla (cerrado). */
static void webapi_kdf(const uint8_t salt[16], const char *pass, uint8_t out[32])
{
    memset(out, 0, 32);
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)pass,
                                  strlen(pass), salt, 16, WEBAPI_KDF_ITERS, 32, out);
}

/* HMAC-SHA256(key, msg). Firma compatible con webapi_hmac_fn. Vía PSA Crypto
 * (la API MD-HMAC clásica es privada en mbedTLS 4). Si algo falla, out queda
 * en ceros ⇒ la verificación no casará (falla cerrado). */
static void webapi_hmac(const uint8_t *key, size_t key_len, const uint8_t *msg,
                        size_t msg_len, uint8_t out[32])
{
    memset(out, 0, 32);
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_key_id_t k = 0;
    if (psa_import_key(&attr, key, key_len, &k) != PSA_SUCCESS) {
        return;
    }
    size_t olen = 0;
    psa_mac_compute(k, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, msg_len, out, 32, &olen);
    psa_destroy_key(k);
}

/* --- helpers HTTP --- */

static esp_err_t send_json(httpd_req_t *req, const char *status, const char *json)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_err(httpd_req_t *req, const char *status, const char *msg)
{
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    if (n < 0 || n >= (int)sizeof(buf)) {
        buf[0] = '\0';
    }
    return send_json(req, status, buf);
}

/* Lee el cuerpo entero (≤ BODY_MAX) en buf; devuelve longitud o -1. */
static int recv_body(httpd_req_t *req, char *buf, size_t cap)
{
    if (req->content_len >= cap) {
        return -1; /* demasiado grande: entrada hostil acotada */
    }
    size_t total = 0;
    while (total < req->content_len) {
        int r = httpd_req_recv(req, buf + total, cap - 1 - total);
        if (r <= 0) {
            return -1;
        }
        total += (size_t)r;
    }
    buf[total] = '\0';
    return (int)total;
}

/* Extrae el valor string del campo "key" de un JSON plano en dst (acotado).
 * Minimalista y defensivo (no un parser completo): busca "key"…:…"valor".
 * false si no está o no cabe. No interpreta escapes salvo comillas. */
static bool json_field(const char *body, const char *key, char *dst, size_t cap)
{
    char pat[32];
    int pn = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pn < 0 || pn >= (int)sizeof(pat)) {
        return false;
    }
    const char *p = strstr(body, pat);
    if (p == NULL) {
        return false;
    }
    p = strchr(p + pn, ':');
    if (p == NULL) {
        return false;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != '"') {
        return false;
    }
    p++;
    size_t i = 0;
    while (*p != '"' && *p != '\0') {
        if (i + 1 >= cap) {
            return false; /* no cabe */
        }
        dst[i++] = *p++;
    }
    if (*p != '"') {
        return false; /* string sin cerrar */
    }
    dst[i] = '\0';
    return true;
}

/* --- middleware de sesión --- */

/* Extrae el token (WEBAPI_TOKEN_LEN chars) de la cookie esphole_session a
 * out[WEBAPI_TOKEN_LEN+1]. false si no está o tiene longitud incorrecta. */
static bool cookie_token(httpd_req_t *req, char *out)
{
    size_t clen = httpd_req_get_hdr_value_len(req, "Cookie");
    if (clen == 0 || clen > 512) {
        return false;
    }
    char cookie[513];
    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie)) != ESP_OK) {
        return false;
    }
    const char *p = strstr(cookie, COOKIE_NAME "=");
    if (p == NULL) {
        return false;
    }
    p += strlen(COOKIE_NAME "=");
    size_t i = 0;
    while (p[i] != '\0' && p[i] != ';' && p[i] != ' ' && i < WEBAPI_TOKEN_LEN) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
    return i == WEBAPI_TOKEN_LEN;
}

/* ¿la petición trae una cookie de sesión válida? */
static bool has_valid_session(httpd_req_t *req)
{
    char token[WEBAPI_TOKEN_LEN + 1];
    if (!cookie_token(req, token)) {
        return false;
    }
    return webapi_session_valid(&s_sessions, token, now_s());
}

/* Puerta común de los endpoints protegidos: 401 si no hay sesión. */
static bool guard(httpd_req_t *req)
{
    if (has_valid_session(req)) {
        return true;
    }
    send_err(req, "401 Unauthorized", "no autenticado");
    return false;
}

static void set_session_cookie(httpd_req_t *req, const char *token)
{
    /* httpd_resp_set_hdr NO copia el valor: guarda el puntero y lo serializa
     * al enviar la respuesta. Debe persistir hasta entonces ⇒ estático (la
     * tarea HTTP es de un solo hilo, sin reentrancia). */
    static char c[128];
    snprintf(c, sizeof(c),
             COOKIE_NAME "=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Strict",
             token, WEBAPI_SESSION_TTL_S);
    httpd_resp_set_hdr(req, "Set-Cookie", c);
}

/* --- estáticos desde SPIFFS --- */

static const char *content_type_de(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (dot == NULL) {
        return "application/octet-stream";
    }
    if (strcmp(dot, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(dot, ".js") == 0) return "text/javascript";
    if (strcmp(dot, ".css") == 0) return "text/css";
    if (strcmp(dot, ".json") == 0) return "application/json";
    if (strcmp(dot, ".ico") == 0) return "image/x-icon";
    if (strcmp(dot, ".svg") == 0) return "image/svg+xml";
    return "application/octet-stream";
}

static esp_err_t h_static(httpd_req_t *req)
{
    if (!s_spiffs_ok) {
        /* AB-12: sin UI empaquetada, la API sigue viva; solo faltan estáticos. */
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_send(req, "UI no instalada (particion www vacia)",
                               HTTPD_RESP_USE_STRLEN);
    }
    /* mapea "/" → "/index.html"; rechaza traversal con ".." */
    char path[128];
    const char *uri = req->uri;
    if (strstr(uri, "..") != NULL) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_send(req, "ruta invalida", HTTPD_RESP_USE_STRLEN);
    }
    if (strcmp(uri, "/") == 0) {
        uri = "/index.html";
    }
    int n = snprintf(path, sizeof(path), WWW_BASE "%s", uri);
    if (n < 0 || n >= (int)sizeof(path)) {
        httpd_resp_set_status(req, "414 URI Too Long");
        return httpd_resp_send(req, "ruta larga", HTTPD_RESP_USE_STRLEN);
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_send(req, "no encontrado", HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_set_type(req, content_type_de(path));
    char chunk[512];
    size_t r;
    while ((r = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (httpd_resp_send_chunk(req, chunk, r) != ESP_OK) {
            fclose(f);
            return ESP_FAIL;
        }
    }
    fclose(f);
    return httpd_resp_send_chunk(req, NULL, 0); /* fin */
}

/* --- setup / challenge / login --- */

static esp_err_t h_setup(httpd_req_t *req)
{
    uint8_t h[32], salt[16];
    if (config_get_admin(h, salt)) {
        /* ya hay admin: /api/setup solo sirve la primera vez (AB-02) */
        return send_err(req, "409 Conflict", "ya configurado");
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char pass[PASS_MAX + 2];
    if (!json_field(body, "password", pass, sizeof(pass))) {
        return send_err(req, "400 Bad Request", "falta password");
    }
    size_t pl = strlen(pass);
    if (pl < PASS_MIN || pl > PASS_MAX) {
        return send_err(req, "400 Bad Request", "longitud de password 8..64");
    }
    esp_fill_random(salt, sizeof(salt));
    webapi_kdf(salt, pass, h);
    if (!config_set_admin(h, salt)) {
        return send_err(req, "500 Internal Server Error", "no se pudo guardar");
    }
    /* auto-login tras el setup: crea sesión para no re-pedir credencial */
    char token[WEBAPI_TOKEN_LEN + 1];
    rand_hex16(token);
    webapi_session_create(&s_sessions, token, now_s());
    set_session_cookie(req, token);
    ESP_LOGI(TAG, "admin configurada");
    return send_json(req, "200 OK", "{\"ok\":true}");
}

static esp_err_t h_challenge(httpd_req_t *req)
{
    uint8_t h[32], salt[16];
    if (!config_get_admin(h, salt)) {
        return send_err(req, "409 Conflict", "sin admin: usa /api/setup");
    }
    char nonce[WEBAPI_NONCE_LEN + 1];
    rand_hex16(nonce);
    webapi_nonce_issue(&s_nonces, nonce, now_s());
    char salt_hex[33];
    to_hex(salt, sizeof(salt), salt_hex);
    char out[128];
    snprintf(out, sizeof(out), "{\"nonce\":\"%s\",\"salt\":\"%s\"}", nonce, salt_hex);
    return send_json(req, "200 OK", out);
}

static esp_err_t h_login(httpd_req_t *req)
{
    uint32_t now = now_s();
    /* ventana anti-fuerza-bruta */
    if (now - s_login_win_start >= LOGIN_WIN_S) {
        s_login_win_start = now;
        s_login_fails = 0;
    }
    if (s_login_fails >= LOGIN_MAX_FAILS) {
        return send_err(req, "429 Too Many Requests", "demasiados intentos");
    }
    uint8_t h[32], salt[16];
    if (!config_get_admin(h, salt)) {
        return send_err(req, "409 Conflict", "sin admin");
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char nonce[WEBAPI_NONCE_LEN + 2], resp[80];
    if (!json_field(body, "nonce", nonce, sizeof(nonce)) ||
        !json_field(body, "resp", resp, sizeof(resp))) {
        return send_err(req, "400 Bad Request", "faltan campos");
    }
    /* el nonce es de un solo uso: si no existe/expiró, rechazo (AB-04) */
    if (!webapi_nonce_take(&s_nonces, nonce, now) ||
        !webapi_verify_challenge(h, nonce, resp, webapi_hmac)) {
        s_login_fails++;
        return send_err(req, "401 Unauthorized", "credenciales invalidas");
    }
    char token[WEBAPI_TOKEN_LEN + 1];
    rand_hex16(token);
    webapi_session_create(&s_sessions, token, now);
    set_session_cookie(req, token);
    ESP_LOGI(TAG, "login correcto");
    return send_json(req, "200 OK", "{\"ok\":true}");
}

static esp_err_t h_logout(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char token[WEBAPI_TOKEN_LEN + 1];
    if (cookie_token(req, token)) {
        webapi_session_invalidate(&s_sessions, token);
    }
    /* borra la cookie en el cliente (Max-Age=0). Literal estático ⇒ persiste. */
    httpd_resp_set_hdr(req, "Set-Cookie",
                       COOKIE_NAME "=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict");
    ESP_LOGI(TAG, "logout");
    return send_json(req, "200 OK", "{\"ok\":true}");
}

/* Cambio de contraseña: exige probar la contraseña ACTUAL por desafío-respuesta
 * (una sesión robada no basta) y fija la nueva; cierra todas las sesiones. */
static esp_err_t h_password(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    uint8_t h_cur[32], salt_cur[16];
    if (!config_get_admin(h_cur, salt_cur)) {
        return send_err(req, "409 Conflict", "sin admin");
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char nonce[WEBAPI_NONCE_LEN + 2], resp[80], newp[PASS_MAX + 2];
    if (!json_field(body, "nonce", nonce, sizeof(nonce)) ||
        !json_field(body, "resp", resp, sizeof(resp)) ||
        !json_field(body, "new_password", newp, sizeof(newp))) {
        return send_err(req, "400 Bad Request", "faltan campos");
    }
    size_t pl = strlen(newp);
    if (pl < PASS_MIN || pl > PASS_MAX) {
        return send_err(req, "400 Bad Request", "longitud de password 8..64");
    }
    /* prueba de la contraseña actual (nonce de un solo uso + HMAC) */
    if (!webapi_nonce_take(&s_nonces, nonce, now_s()) ||
        !webapi_verify_challenge(h_cur, nonce, resp, webapi_hmac)) {
        return send_err(req, "401 Unauthorized", "contraseña actual incorrecta");
    }
    uint8_t salt_new[16], h_new[32];
    esp_fill_random(salt_new, sizeof(salt_new));
    webapi_kdf(salt_new, newp, h_new);
    if (!config_set_admin(h_new, salt_new)) {
        return send_err(req, "500 Internal Server Error", "no se pudo guardar");
    }
    /* cierra TODAS las sesiones: hay que volver a entrar con la nueva contraseña */
    webapi_sessions_init(&s_sessions);
    ESP_LOGI(TAG, "contraseña de admin cambiada; sesiones cerradas");
    return send_json(req, "200 OK", "{\"ok\":true}");
}

/* --- endpoints protegidos --- */

static esp_err_t h_status(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    metrics_snapshot_t m;
    metrics_snapshot(&m);
    webapi_sysinfo_t sys = {0};
    sys.heap_libre = (uint32_t)esp_get_free_heap_size();
    sys.uptime_s = now_s();
    upstream_health(sys.upstreams.salud, &sys.upstreams.count);
    char buf[STATUS_JSON_MAX];
    size_t n = webapi_status_json(&m, &sys, buf, sizeof(buf));
    if (n == 0) {
        return send_err(req, "500 Internal Server Error", "json");
    }
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_config_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char buf[256];
    size_t n = webapi_config_json(s_cfg, buf, sizeof(buf));
    if (n == 0) {
        return send_err(req, "500 Internal Server Error", "json");
    }
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_upstreams_put(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char body[BODY_MAX];
    int bl = recv_body(req, body, sizeof(body));
    if (bl < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    /* parte de la config vigente y solo cambia upstreams; si algo falla, la
     * config guardada no se toca (FR-007). */
    esphole_config_t nueva = *s_cfg;
    webapi_cfg_err_t e = webapi_parse_upstreams(body, (size_t)bl, &nueva);
    if (e != WEBAPI_CFG_OK) {
        const char *msg = (e == WEBAPI_CFG_EMPTY)      ? "lista vacia"
                          : (e == WEBAPI_CFG_TOO_MANY) ? "demasiados upstreams"
                                                       : "direccion invalida";
        return send_err(req, "400 Bad Request", msg);
    }
    if (!config_save(&nueva)) {
        return send_err(req, "500 Internal Server Error", "no se pudo guardar");
    }
    /* aplicar en caliente es delicado (pcb/salud en tcpip); reiniciamos de
     * forma controlada — al arrancar se cargan los upstreams nuevos (AB-07). */
    send_json(req, "200 OK", "{\"ok\":true,\"reiniciando\":true}");
    ESP_LOGW(TAG, "upstreams actualizados: reiniciando");
    vTaskDelay(pdMS_TO_TICKS(400)); /* deja salir la respuesta */
    esp_restart();
    return ESP_OK; /* inalcanzable */
}

static esp_err_t h_cache_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char buf[96];
    snprintf(buf, sizeof(buf), "{\"entradas\":%u,\"capacidad\":%u}",
             (unsigned)net_dns_cache_count(),
             (unsigned)(s_cfg ? s_cfg->cache_cap : 0));
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_cache_delete(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    net_dns_cache_flush();
    ESP_LOGI(TAG, "cache vaciada por la API");
    return send_json(req, "200 OK", "{\"ok\":true,\"entradas\":0}");
}

/* --- lista de bloqueo (spec 004) --- */

static const char *lu_estado_str(lu_estado_t e)
{
    switch (e) {
    case LU_IDLE: return "idle";
    case LU_DOWNLOADING: return "downloading";
    case LU_BUILDING: return "building";
    case LU_WRITING: return "writing";
    case LU_OK: return "ok";
    case LU_ERROR: return "error";
    }
    return "?";
}

static bool esquema_http(const char *url)
{
    return strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0;
}

static esp_err_t h_blocklist_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    listupdate_status_t st;
    listupdate_status(&st);
    char url[BL_URL_MAX + 1];
    config_get_blocklist_url(url, sizeof(url));
    char buf[512];
    snprintf(buf, sizeof(buf),
             "{\"url\":\"%s\",\"count\":%u,\"en_curso\":%s,\"estado\":\"%s\","
             "\"descargados\":%u,\"error\":\"%s\",\"cuando_s\":%u}",
             url, (unsigned)st.count, st.en_curso ? "true" : "false",
             lu_estado_str(st.estado), (unsigned)st.descargados, st.error,
             (unsigned)st.cuando_s);
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_blocklist_put(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char url[BL_URL_MAX + 2];
    if (!json_field(body, "url", url, sizeof(url))) {
        return send_err(req, "400 Bad Request", "falta url");
    }
    if (!esquema_http(url)) {
        return send_err(req, "400 Bad Request", "esquema no soportado (http/https)");
    }
    if (!config_set_blocklist_url(url)) {
        return send_err(req, "400 Bad Request", "url demasiado larga");
    }
    return send_json(req, "200 OK", "{\"ok\":true}");
}

static esp_err_t h_blocklist_update(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    listupdate_status_t st;
    listupdate_status(&st);
    if (st.en_curso) {
        return send_err(req, "409 Conflict", "ya hay una actualizacion en curso");
    }
    char body[BODY_MAX];
    int n = recv_body(req, body, sizeof(body));
    char url[BL_URL_MAX + 2];
    bool tiene = false;
    if (n > 0 && json_field(body, "url", url, sizeof(url))) {
        if (!esquema_http(url)) {
            return send_err(req, "400 Bad Request", "esquema no soportado");
        }
        if (!config_set_blocklist_url(url)) {
            return send_err(req, "400 Bad Request", "url demasiado larga");
        }
        tiene = true;
    }
    if (!tiene) {
        config_get_blocklist_url(url, sizeof(url));
    }
    if (!listupdate_trigger(url)) {
        return send_err(req, "400 Bad Request", "no se pudo iniciar");
    }
    return send_json(req, "202 Accepted", "{\"ok\":true,\"iniciando\":true}");
}

/* --- DHCP (spec 006) --- */

static void ip_dotted(uint32_t ip, char *out, size_t cap)
{
    snprintf(out, cap, "%u.%u.%u.%u", (unsigned)((ip >> 24) & 0xff),
             (unsigned)((ip >> 16) & 0xff), (unsigned)((ip >> 8) & 0xff),
             (unsigned)(ip & 0xff));
}

static bool parse_ipv4_host(const char *s, uint32_t *out)
{
    unsigned a, b, c, d;
    char extra;
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) {
        return false; /* 5 campos = basura sobrante */
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return false;
    }
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

static esp_err_t h_dhcp_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    net_dhcp_status_t st;
    net_dhcp_status(&st);
    static char buf[4096]; /* hasta 32 leases; tarea HTTP de un solo hilo */
    char ps[16], pe[16], gw[16], dns[16], mk[16];
    ip_dotted(st.pool_start, ps, sizeof(ps));
    ip_dotted(st.pool_end, pe, sizeof(pe));
    ip_dotted(st.gateway, gw, sizeof(gw));
    ip_dotted(st.dns, dns, sizeof(dns));
    ip_dotted(st.mask, mk, sizeof(mk));
    int w = snprintf(buf, sizeof(buf),
                     "{\"enabled\":%s,\"pool_start\":\"%s\",\"pool_end\":\"%s\","
                     "\"gateway\":\"%s\",\"dns\":\"%s\",\"mask\":\"%s\","
                     "\"lease_time\":%u,\"leases\":[",
                     st.enabled ? "true" : "false", ps, pe, gw, dns, mk,
                     (unsigned)st.lease_time);
    for (uint32_t i = 0; i < st.count && w < (int)sizeof(buf) - 128; i++) {
        char lip[16];
        ip_dotted(st.leases[i].ip, lip, sizeof(lip));
        const uint8_t *m = st.leases[i].mac;
        w += snprintf(buf + w, sizeof(buf) - w,
                      "%s{\"ip\":\"%s\",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                      "\"hostname\":\"%s\",\"expira_s\":%u}",
                      i ? "," : "", lip, m[0], m[1], m[2], m[3], m[4], m[5],
                      st.leases[i].hostname, (unsigned)st.leases[i].expira_s);
    }
    w += snprintf(buf + w, sizeof(buf) - w, "]}");
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_dhcp_put(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char v[64];
    /* enabled: obligatorio ("true"/"false") */
    if (!json_field(body, "enabled", v, sizeof(v))) {
        return send_err(req, "400 Bad Request", "falta enabled");
    }
    bool enabled = (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);
    uint32_t ps = 0, pe = 0, lt = 0;
    if (json_field(body, "pool_start", v, sizeof(v)) && v[0] &&
        !parse_ipv4_host(v, &ps)) {
        return send_err(req, "400 Bad Request", "pool_start invalido");
    }
    if (json_field(body, "pool_end", v, sizeof(v)) && v[0] &&
        !parse_ipv4_host(v, &pe)) {
        return send_err(req, "400 Bad Request", "pool_end invalido");
    }
    if (ps != 0 && pe != 0 && ps > pe) {
        return send_err(req, "400 Bad Request", "rango invalido (inicio>fin)");
    }
    if (json_field(body, "lease_time", v, sizeof(v)) && v[0]) {
        lt = (uint32_t)strtoul(v, NULL, 10);
    }
    if (!config_set_dhcp(enabled, ps, pe, lt)) {
        return send_err(req, "500 Internal Server Error", "no se pudo guardar");
    }
    net_dhcp_start(); /* aplica: arranca/para/recarga según la config nueva */
    return send_json(req, "200 OK", "{\"ok\":true}");
}

/* --- upstream DoT (spec 007) --- */

/* ¿es un hostname/SNI válido? [A-Za-z0-9.-], no vacío, sin exceder DOT_SNI_MAX. */
static bool sni_valido(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= DOT_SNI_MAX) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return false;
        }
    }
    return true;
}

/* Extrae hasta CONFIG_UPSTREAMS_MAX strings del array JSON "sni":[...] en 'body'.
 * Devuelve el número extraído, o -1 si el array está mal formado o algún SNI es
 * inválido. Si no hay clave "sni", devuelve 0 (sin cambios). */
static int parse_sni_array(const char *body, char out[][DOT_SNI_MAX])
{
    const char *p = strstr(body, "\"sni\"");
    if (p == NULL) {
        return 0; /* ausente: el llamador conserva los SNI actuales */
    }
    p = strchr(p + 5, ':');
    if (p == NULL) {
        return -1;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != '[') {
        return -1;
    }
    p++;
    int count = 0;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') {
            p++;
        }
        if (*p == ']') {
            break;
        }
        if (*p != '"') {
            return -1; /* elemento no-string */
        }
        p++;
        if (count >= CONFIG_UPSTREAMS_MAX) {
            return -1; /* más SNI que upstreams */
        }
        size_t i = 0;
        while (*p != '"' && *p != '\0') {
            if (i + 1 >= DOT_SNI_MAX) {
                return -1; /* no cabe */
            }
            out[count][i++] = *p++;
        }
        if (*p != '"') {
            return -1; /* string sin cerrar */
        }
        out[count][i] = '\0';
        if (!sni_valido(out[count])) {
            return -1;
        }
        count++;
        p++; /* pasa la comilla de cierre */
    }
    return count;
}

static esp_err_t h_dot_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    bool en_cfg = false;
    char sni[CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX];
    config_get_dot(&en_cfg, sni);
    net_dot_status_t st;
    net_dot_status(&st);
    char buf[640];
    int w = snprintf(buf, sizeof(buf),
                     "{\"enabled\":%s,\"connected\":%s,\"active\":%d,"
                     "\"served\":%u,\"servfail\":%u,\"dropped\":%u,"
                     "\"last_error\":\"%s\",\"sni\":[",
                     en_cfg ? "true" : "false", st.connected ? "true" : "false",
                     st.active, (unsigned)st.served, (unsigned)st.servfail,
                     (unsigned)st.dropped, st.last_error);
    for (int i = 0; i < CONFIG_UPSTREAMS_MAX && w < (int)sizeof(buf) - 96; i++) {
        w += snprintf(buf + w, sizeof(buf) - w, "%s\"%s\"", i ? "," : "", sni[i]);
    }
    w += snprintf(buf + w, sizeof(buf) - w, "]}");
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_dot_put(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char v[16];
    if (!json_field(body, "enabled", v, sizeof(v))) {
        return send_err(req, "400 Bad Request", "falta enabled");
    }
    bool enabled = (strcmp(v, "true") == 0 || strcmp(v, "1") == 0);

    /* SNI: si vienen, se validan y reemplazan; si no, se conservan los actuales. */
    char sni[CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX];
    bool en_cur = false;
    config_get_dot(&en_cur, sni); /* rellena con los SNI actuales (o defaults) */
    int n = parse_sni_array(body, sni);
    if (n < 0) {
        return send_err(req, "400 Bad Request", "sni invalido");
    }

    if (!config_set_dot(enabled, sni)) {
        return send_err(req, "500 Internal Server Error", "no se pudo guardar");
    }
    /* aplica: conmuta a DoT / restaura UDP / recarga según la config nueva */
    if (enabled) {
        net_dot_start();
    } else {
        net_dot_stop();
    }
    return send_json(req, "200 OK", "{\"ok\":true}");
}

/* --- registro de clientes (spec 008) --- */

/* Formatea un ip_addr16_t: v4 punteado; v6 en 8 grupos hex (sin comprimir). */
static void ip16_str(const ip_addr16_t *ip, char *out, size_t cap)
{
    if (ip->family == ESPHOLE_AF_V4) {
        snprintf(out, cap, "%u.%u.%u.%u", ip->bytes[0], ip->bytes[1], ip->bytes[2],
                 ip->bytes[3]);
    } else {
        const uint8_t *b = ip->bytes;
        snprintf(out, cap, "%x:%x:%x:%x:%x:%x:%x:%x", (b[0] << 8) | b[1],
                 (b[2] << 8) | b[3], (b[4] << 8) | b[5], (b[6] << 8) | b[7],
                 (b[8] << 8) | b[9], (b[10] << 8) | b[11], (b[12] << 8) | b[13],
                 (b[14] << 8) | b[15]);
    }
}

static esp_err_t h_clients_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    static client_ent_t snap[CLIENTS_TABLE]; /* tarea HTTP de un solo hilo */
    size_t n = net_dns_clients_snapshot(snap, CLIENTS_TABLE);
    /* ordena por visto más reciente (visto_s absoluto mayor primero); n≤64 */
    for (size_t i = 1; i < n; i++) {
        client_ent_t key = snap[i];
        size_t j = i;
        while (j > 0 && snap[j - 1].visto_s < key.visto_s) {
            snap[j] = snap[j - 1];
            j--;
        }
        snap[j] = key;
    }
    uint32_t now = now_s();
    static char buf[4096]; /* hasta 64 clientes */
    int w = snprintf(buf, sizeof(buf), "[");
    for (size_t i = 0; i < n && w < (int)sizeof(buf) - 96; i++) {
        char ips[46];
        ip16_str(&snap[i].ip, ips, sizeof(ips));
        uint32_t ago = (now >= snap[i].visto_s) ? (now - snap[i].visto_s) : 0;
        w += snprintf(buf + w, sizeof(buf) - w,
                      "%s{\"ip\":\"%s\",\"total\":%u,\"blocked\":%u,\"visto_s\":%u}",
                      i ? "," : "", ips, (unsigned)snap[i].total,
                      (unsigned)snap[i].blocked, (unsigned)ago);
    }
    w += snprintf(buf + w, sizeof(buf) - w, "]");
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_clients_delete(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    net_dns_clients_reset();
    return send_json(req, "200 OK", "{\"ok\":true}");
}

/* --- firmware / OTA (spec 005) --- */

static const char *ota_estado_str(ota_estado_t e)
{
    switch (e) {
    case OTA_IDLE: return "idle";
    case OTA_DOWNLOADING: return "downloading";
    case OTA_DONE: return "done";
    case OTA_ERROR: return "error";
    }
    return "?";
}

static esp_err_t h_firmware_get(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    char ver[40], slot[16];
    otaupdate_running_version(ver, sizeof(ver));
    otaupdate_running_slot(slot, sizeof(slot));
    otaupdate_status_t st;
    otaupdate_status(&st);
    char buf[384];
    snprintf(buf, sizeof(buf),
             "{\"version\":\"%s\",\"slot\":\"%s\",\"estado\":\"%s\",\"leido\":%u,"
             "\"total\":%u,\"error\":\"%s\",\"cuando_s\":%u,\"en_curso\":%s}",
             ver, slot, ota_estado_str(st.estado), (unsigned)st.leido,
             (unsigned)st.total, st.error, (unsigned)st.cuando_s,
             st.en_curso ? "true" : "false");
    return send_json(req, "200 OK", buf);
}

static esp_err_t h_firmware_update(httpd_req_t *req)
{
    if (!guard(req)) {
        return ESP_OK;
    }
    otaupdate_status_t st;
    otaupdate_status(&st);
    if (st.en_curso) {
        return send_err(req, "409 Conflict", "ya hay una OTA en curso");
    }
    char body[BODY_MAX];
    if (recv_body(req, body, sizeof(body)) < 0) {
        return send_err(req, "400 Bad Request", "cuerpo invalido");
    }
    char url[BL_URL_MAX + 2];
    if (!json_field(body, "url", url, sizeof(url))) {
        return send_err(req, "400 Bad Request", "falta url");
    }
    if (!esquema_http(url)) {
        return send_err(req, "400 Bad Request", "esquema no soportado (http/https)");
    }
    if (!otaupdate_trigger(url)) {
        return send_err(req, "400 Bad Request", "no se pudo iniciar");
    }
    return send_json(req, "202 Accepted", "{\"ok\":true,\"iniciando\":true}");
}

/* --- montaje SPIFFS + arranque --- */

static void montar_spiffs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = WWW_BASE,
        .partition_label = "www",
        .max_files = 4,
        .format_if_mount_failed = false, /* la UI es de solo lectura (spiffsgen) */
    };
    esp_err_t e = esp_vfs_spiffs_register(&conf);
    if (e != ESP_OK) {
        /* FR-011: sin partición/UI, la API sigue. No es fatal. */
        ESP_LOGW(TAG, "SPIFFS www no montada (%s): API sin UI", esp_err_to_name(e));
        s_spiffs_ok = false;
        return;
    }
    s_spiffs_ok = true;
    size_t total = 0, usado = 0;
    esp_spiffs_info("www", &total, &usado);
    ESP_LOGI(TAG, "SPIFFS www montada: %u/%u B", (unsigned)usado, (unsigned)total);
}

bool webapi_start(const esphole_config_t *cfg)
{
    if (s_http != NULL) {
        return true; /* idempotente */
    }
    s_cfg = cfg;
    webapi_sessions_init(&s_sessions);
    webapi_nonces_init(&s_nonces);
    s_login_win_start = now_s();
    psa_crypto_init(); /* idempotente; necesario para el HMAC vía PSA */

    montar_spiffs();

    httpd_config_t hc = HTTPD_DEFAULT_CONFIG();
    hc.max_uri_handlers = 26;
    hc.uri_match_fn = httpd_uri_match_wildcard; /* habilita el comodin del catch-all */
    hc.lru_purge_enable = true;
    /* stack propio de la tarea HTTP: el manejo de TLS/cripto necesita holgura */
    hc.stack_size = 6144;
    if (httpd_start(&s_http, &hc) != ESP_OK) {
        ESP_LOGE(TAG, "httpd no arrancó: sin interfaz web (el DNS sigue)");
        return false;
    }

    const httpd_uri_t rutas[] = {
        {.uri = "/api/setup", .method = HTTP_POST, .handler = h_setup},
        {.uri = "/api/challenge", .method = HTTP_GET, .handler = h_challenge},
        {.uri = "/api/login", .method = HTTP_POST, .handler = h_login},
        {.uri = "/api/logout", .method = HTTP_POST, .handler = h_logout},
        {.uri = "/api/password", .method = HTTP_POST, .handler = h_password},
        {.uri = "/api/status", .method = HTTP_GET, .handler = h_status},
        {.uri = "/api/config", .method = HTTP_GET, .handler = h_config_get},
        {.uri = "/api/config/upstreams", .method = HTTP_PUT, .handler = h_upstreams_put},
        {.uri = "/api/cache", .method = HTTP_GET, .handler = h_cache_get},
        {.uri = "/api/cache", .method = HTTP_DELETE, .handler = h_cache_delete},
        {.uri = "/api/blocklist", .method = HTTP_GET, .handler = h_blocklist_get},
        {.uri = "/api/blocklist", .method = HTTP_PUT, .handler = h_blocklist_put},
        {.uri = "/api/blocklist/update", .method = HTTP_POST, .handler = h_blocklist_update},
        {.uri = "/api/firmware", .method = HTTP_GET, .handler = h_firmware_get},
        {.uri = "/api/firmware/update", .method = HTTP_POST, .handler = h_firmware_update},
        {.uri = "/api/dhcp", .method = HTTP_GET, .handler = h_dhcp_get},
        {.uri = "/api/dhcp", .method = HTTP_PUT, .handler = h_dhcp_put},
        {.uri = "/api/dot", .method = HTTP_GET, .handler = h_dot_get},
        {.uri = "/api/dot", .method = HTTP_PUT, .handler = h_dot_put},
        {.uri = "/api/clients", .method = HTTP_GET, .handler = h_clients_get},
        {.uri = "/api/clients", .method = HTTP_DELETE, .handler = h_clients_delete},
        {.uri = "/*", .method = HTTP_GET, .handler = h_static}, /* último: catch-all */
    };
    for (size_t i = 0; i < sizeof(rutas) / sizeof(rutas[0]); i++) {
        httpd_register_uri_handler(s_http, &rutas[i]);
    }
    uint8_t hh[32], ss[16];
    ESP_LOGI(TAG, "webapi lista (estado: %s)",
             config_get_admin(hh, ss) ? "NORMAL" : "SETUP");
    return true;
}
