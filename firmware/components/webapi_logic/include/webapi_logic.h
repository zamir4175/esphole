/*
 * webapi_logic — lógica pura de la web/API (PURO). spec 003.
 * Contrato: specs/003-api-web/contracts/webapi-logic.md.
 * C11, sin dependencias de ESP-IDF. Toda entrada de la API es hostil.
 * Reloj y aleatoriedad inyectados.
 */
#ifndef ESPHOLE_WEBAPI_LOGIC_H
#define ESPHOLE_WEBAPI_LOGIC_H

#include "config_nvs.h"
#include "esphole_types.h"
#include "metrics.h"

/* --- 1. Serialización de estado a JSON --- */

typedef struct {
    uint32_t heap_libre;
    uint32_t uptime_s;
    struct {
        uint8_t count;
        uint8_t salud[4]; /* 0=sano, 1=sospechoso, 2=caido — por upstream */
    } upstreams;
} webapi_sysinfo_t;

/* Serializa métricas + sysinfo a JSON en buf (NUL-terminado). Devuelve bytes
 * escritos (sin el NUL), 0 si no cabe. Solo refleja los contadores del core. */
size_t webapi_status_json(const metrics_snapshot_t *m,
                          const webapi_sysinfo_t *sys, char *buf, size_t cap);

/* Serializa la config editable (upstreams) a JSON. */
size_t webapi_config_json(const esphole_config_t *cfg, char *buf, size_t cap);

/* --- 2. Validación/parseo de la config entrante --- */

typedef enum {
    WEBAPI_CFG_OK = 0,
    WEBAPI_CFG_MALFORMED, /* JSON o campos inválidos */
    WEBAPI_CFG_EMPTY,     /* lista de upstreams vacía */
    WEBAPI_CFG_TOO_MANY,  /* más de CONFIG_UPSTREAMS_MAX */
} webapi_cfg_err_t;

/* Parsea {"upstreams":["1.1.1.1", ...]} y valida cada dirección (v4/v6),
 * 1..CONFIG_UPSTREAMS_MAX. Rellena out->upstream_* sin tocar el resto. No
 * modifica nada si devuelve error (la config vigente no se corrompe). */
webapi_cfg_err_t webapi_parse_upstreams(const char *body, size_t len,
                                        esphole_config_t *out);

/* --- 3. Sesiones (tabla fija, reloj inyectado) --- */

#define WEBAPI_SESSIONS 4
#define WEBAPI_TOKEN_LEN 32 /* hex de 16 bytes aleatorios */
#define WEBAPI_SESSION_TTL_S 1800

typedef struct {
    char token[WEBAPI_TOKEN_LEN + 1];
    uint32_t expira; /* segundos monotónicos */
    bool en_uso;
} webapi_session_t;

typedef struct {
    webapi_session_t s[WEBAPI_SESSIONS];
} webapi_sessions_t;

void webapi_sessions_init(webapi_sessions_t *t);
void webapi_session_create(webapi_sessions_t *t, const char *token, uint32_t now);
bool webapi_session_valid(webapi_sessions_t *t, const char *token, uint32_t now);
/* Cierra la sesión de 'token' (logout). No-op si no existe o token es NULL. */
void webapi_session_invalidate(webapi_sessions_t *t, const char *token);

/* --- 4. Nonces de login (un solo uso) --- */

#define WEBAPI_NONCES 8
#define WEBAPI_NONCE_LEN 32
#define WEBAPI_NONCE_TTL_S 60

typedef struct {
    char nonce[WEBAPI_NONCE_LEN + 1];
    uint32_t expira;
    bool en_uso;
} webapi_nonce_t;

typedef struct {
    webapi_nonce_t n[WEBAPI_NONCES];
} webapi_nonces_t;

void webapi_nonces_init(webapi_nonces_t *t);
void webapi_nonce_issue(webapi_nonces_t *t, const char *nonce, uint32_t now);
/* Consume un nonce: true si existía y no expiró (y lo INVALIDA); false si no. */
bool webapi_nonce_take(webapi_nonces_t *t, const char *nonce, uint32_t now);

/* --- 5. Verificación del desafío-respuesta (HMAC inyectable) --- */

typedef void (*webapi_hmac_fn)(const uint8_t *key, size_t key_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t out[32]);

/* ¿resp_hex (64 hex) == HMAC-SHA256(key=h, msg=nonce)? Tiempo constante. La
 * contraseña nunca entra aquí: solo su hash 'h' (32 B) y el nonce. */
bool webapi_verify_challenge(const uint8_t h[32], const char *nonce,
                             const char *resp_hex, webapi_hmac_fn hmac);

#endif /* ESPHOLE_WEBAPI_LOGIC_H */
