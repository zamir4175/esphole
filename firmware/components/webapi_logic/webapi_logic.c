#include "webapi_logic.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Formatea una dirección a texto. v4 "a.b.c.d"; v6 comprimido con "::" en la
 * secuencia de ceros más larga (RFC 5952). out ≥ 40 bytes. */
static void ip_to_str(const ip_addr16_t *a, char *out, size_t cap)
{
    if (a->family == ESPHOLE_AF_V4) {
        snprintf(out, cap, "%u.%u.%u.%u", a->bytes[0], a->bytes[1], a->bytes[2],
                 a->bytes[3]);
        return;
    }
    uint16_t g[8];
    for (int i = 0; i < 8; i++) {
        g[i] = (uint16_t)((a->bytes[i * 2] << 8) | a->bytes[i * 2 + 1]);
    }
    /* secuencia de ceros más larga (≥2 para comprimir) */
    int best_i = -1, best_len = 0, cur_i = -1, cur_len = 0;
    for (int i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (cur_i < 0) {
                cur_i = i;
                cur_len = 1;
            } else {
                cur_len++;
            }
            if (cur_len > best_len) {
                best_len = cur_len;
                best_i = cur_i;
            }
        } else {
            cur_i = -1;
            cur_len = 0;
        }
    }
    if (best_len < 2) {
        best_i = -1;
    }
    /* separador-antes: "::" provee sus dos ':'; los demás grupos anteponen ':'
     * salvo al inicio o justo tras "::" (RFC 5952). */
    size_t w = 0;
    bool first = true;
    for (int i = 0; i < 8;) {
        if (i == best_i) {
            w += (size_t)snprintf(out + w, cap - w, "::");
            i += best_len;
            first = true; /* el grupo siguiente no antepone ':' */
            continue;
        }
        w += (size_t)snprintf(out + w, cap - w, "%s%x", first ? "" : ":", g[i]);
        first = false;
        i++;
    }
    if (w == 0) {
        snprintf(out, cap, "::");
    }
}

/* append acotado: escribe en buf[*w..cap) y avanza *w; devuelve false si no
 * cabe (incluido el NUL). */
static bool jappend(char *buf, size_t cap, size_t *w, const char *fmt, ...)
{
    if (*w >= cap) {
        return false;
    }
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf + *w, cap - *w, fmt, ap);
    va_end(ap);
    if (r < 0 || (size_t)r >= cap - *w) {
        return false;
    }
    *w += (size_t)r;
    return true;
}

size_t webapi_status_json(const metrics_snapshot_t *m,
                          const webapi_sysinfo_t *sys, char *buf, size_t cap)
{
    if (m == NULL || sys == NULL || buf == NULL) {
        return 0;
    }
    size_t w = 0;
    bool ok = jappend(buf, cap, &w,
                      "{\"total\":%u,\"bloqueadas\":%u,\"cache_hits\":%u,"
                      "\"reenviadas\":%u,\"servfail\":%u,\"malformadas\":%u,"
                      "\"ratelimited\":%u,\"no_locales\":%u,"
                      "\"cache_evictions\":%u,",
                      (unsigned)m->contador[MET_TOTAL],
                      (unsigned)m->contador[MET_BLOQUEADAS],
                      (unsigned)m->contador[MET_CACHE_HITS],
                      (unsigned)m->contador[MET_REENVIADAS],
                      (unsigned)m->contador[MET_SERVFAIL],
                      (unsigned)m->contador[MET_MALFORMADAS],
                      (unsigned)m->contador[MET_RATELIMITED],
                      (unsigned)m->contador[MET_NO_LOCALES],
                      (unsigned)m->contador[MET_CACHE_EVICTIONS]);
    ok = ok && jappend(buf, cap, &w, "\"latencia_hist\":[");
    for (int i = 0; ok && i < METRICS_HIST_BUCKETS; i++) {
        ok = jappend(buf, cap, &w, "%s%u", i ? "," : "",
                     (unsigned)m->latencia_hist[i]);
    }
    ok = ok && jappend(buf, cap, &w, "],\"latencia_inline_max_us\":%u,",
                       (unsigned)m->latencia_inline_max_us);
    ok = ok && jappend(buf, cap, &w, "\"upstream_fallos\":[");
    for (int i = 0; ok && i < METRICS_UPSTREAMS; i++) {
        ok = jappend(buf, cap, &w, "%s%u", i ? "," : "",
                     (unsigned)m->upstream_fallos[i]);
    }
    ok = ok && jappend(buf, cap, &w,
                       "],\"heap_libre\":%u,\"uptime_s\":%u,"
                       "\"upstreams_salud\":[",
                       (unsigned)sys->heap_libre, (unsigned)sys->uptime_s);
    for (int i = 0; ok && i < sys->upstreams.count && i < 4; i++) {
        ok = jappend(buf, cap, &w, "%s%u", i ? "," : "",
                     (unsigned)sys->upstreams.salud[i]);
    }
    ok = ok && jappend(buf, cap, &w, "]}");
    return ok ? w : 0;
}

size_t webapi_config_json(const esphole_config_t *cfg, char *buf, size_t cap)
{
    if (cfg == NULL || buf == NULL) {
        return 0;
    }
    size_t w = 0;
    bool ok = jappend(buf, cap, &w, "{\"upstreams\":[");
    for (int i = 0; ok && i < cfg->upstream_count && i < CONFIG_UPSTREAMS_MAX; i++) {
        char ip[48];
        ip_to_str(&cfg->upstream_addr[i], ip, sizeof(ip));
        ok = jappend(buf, cap, &w, "%s\"%s\"", i ? "," : "", ip);
    }
    ok = ok && jappend(buf, cap, &w, "]}");
    return ok ? w : 0;
}

static int hexdig(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_ipv4(const char *s, size_t len, ip_addr16_t *out)
{
    int oct = 0, val = 0, digits = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.') {
            if (digits == 0 || oct >= 3) return false;
            out->bytes[oct++] = (uint8_t)val;
            val = 0;
            digits = 0;
        } else if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            if (++digits > 3 || val > 255) return false;
        } else {
            return false;
        }
    }
    if (oct != 3 || digits == 0) return false;
    out->bytes[3] = (uint8_t)val;
    out->family = ESPHOLE_AF_V4;
    return true;
}

static bool parse_ipv6(const char *s, size_t len, ip_addr16_t *out)
{
    uint16_t g[8];
    int gi = 0, dbl = -1;
    size_t i = 0;
    if (len >= 1 && s[0] == ':') {
        if (len < 2 || s[1] != ':') return false;
        dbl = 0;
        i = 2;
        if (i == len) { /* "::" */
            memset(out->bytes, 0, 16);
            out->family = ESPHOLE_AF_V6;
            return true;
        }
    }
    while (i < len) {
        int val = 0, digits = 0;
        while (i < len && hexdig(s[i]) >= 0) {
            val = val * 16 + hexdig(s[i]);
            if (++digits > 4) return false;
            i++;
        }
        if (digits == 0 || gi >= 8) return false;
        g[gi++] = (uint16_t)val;
        if (i == len) break;
        if (s[i] != ':') return false;
        i++;
        if (i < len && s[i] == ':') { /* "::" */
            if (dbl >= 0) return false;
            dbl = gi;
            i++;
            if (i == len) break;
        } else if (i == len) {
            return false; /* ':' colgante */
        }
    }
    uint16_t full[8];
    if (dbl < 0) {
        if (gi != 8) return false;
        memcpy(full, g, sizeof(full));
    } else {
        int zeros = 8 - gi;
        if (zeros < 1) return false;
        int k = 0;
        for (int j = 0; j < dbl; j++) full[k++] = g[j];
        for (int z = 0; z < zeros; z++) full[k++] = 0;
        for (int j = dbl; j < gi; j++) full[k++] = g[j];
    }
    for (int k = 0; k < 8; k++) {
        out->bytes[k * 2] = (uint8_t)(full[k] >> 8);
        out->bytes[k * 2 + 1] = (uint8_t)(full[k] & 0xFF);
    }
    out->family = ESPHOLE_AF_V6;
    return true;
}

static bool parse_ip(const char *s, size_t len, ip_addr16_t *out)
{
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < len; i++) {
        if (s[i] == ':') return parse_ipv6(s, len, out);
        if (s[i] == '.') return parse_ipv4(s, len, out);
    }
    return false;
}

static const char *find_sub(const char *h, size_t hlen, const char *n)
{
    size_t nlen = strlen(n);
    if (nlen > hlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(h + i, n, nlen) == 0) return h + i;
    }
    return NULL;
}

webapi_cfg_err_t webapi_parse_upstreams(const char *body, size_t len,
                                        esphole_config_t *out)
{
    if (body == NULL || out == NULL) {
        return WEBAPI_CFG_MALFORMED;
    }
    const char *key = find_sub(body, len, "\"upstreams\"");
    if (key == NULL) {
        return WEBAPI_CFG_MALFORMED;
    }
    const char *end = body + len;
    const char *p = key;
    while (p < end && *p != '[') p++;
    if (p >= end) return WEBAPI_CFG_MALFORMED;
    p++; /* tras '[' */

    /* acumula en temporal; solo se copia a out si TODO es válido (FR-007) */
    ip_addr16_t tmp[CONFIG_UPSTREAMS_MAX];
    int count = 0;
    for (;;) {
        while (p < end && (*p == ' ' || *p == ',')) p++;
        if (p < end && *p == ']') break;
        if (p >= end || *p != '"') return WEBAPI_CFG_MALFORMED;
        p++; /* tras la comilla de apertura */
        const char *ini = p;
        while (p < end && *p != '"') p++;
        if (p >= end) return WEBAPI_CFG_MALFORMED; /* string sin cerrar */
        size_t slen = (size_t)(p - ini);
        p++; /* tras la comilla de cierre */
        if (count >= CONFIG_UPSTREAMS_MAX) {
            return WEBAPI_CFG_TOO_MANY;
        }
        if (!parse_ip(ini, slen, &tmp[count])) {
            return WEBAPI_CFG_MALFORMED;
        }
        count++;
    }
    if (count == 0) {
        return WEBAPI_CFG_EMPTY;
    }
    /* válido: ahora sí se toca out */
    for (int i = 0; i < count; i++) {
        out->upstream_addr[i] = tmp[i];
        out->upstream_port[i] = 53;
    }
    out->upstream_count = (uint8_t)count;
    return WEBAPI_CFG_OK;
}

/* comparación en tiempo constante de dos cadenas NUL-terminadas de ≤ max */
static bool ct_eq(const char *a, const char *b, size_t max)
{
    size_t la = strnlen(a, max);
    size_t lb = strnlen(b, max);
    uint8_t diff = (uint8_t)(la ^ lb);
    for (size_t i = 0; i < max; i++) {
        uint8_t ca = (i < la) ? (uint8_t)a[i] : 0;
        uint8_t cb = (i < lb) ? (uint8_t)b[i] : 0;
        diff |= (uint8_t)(ca ^ cb);
    }
    return diff == 0;
}

void webapi_sessions_init(webapi_sessions_t *t)
{
    if (t != NULL) {
        memset(t, 0, sizeof(*t));
    }
}

void webapi_session_create(webapi_sessions_t *t, const char *token, uint32_t now)
{
    if (t == NULL || token == NULL) {
        return;
    }
    int libre = -1, victima = 0;
    for (int i = 0; i < WEBAPI_SESSIONS; i++) {
        if (!t->s[i].en_uso) {
            libre = i;
            break;
        }
        if (t->s[i].expira < t->s[victima].expira) {
            victima = i; /* la de menor expiración = más antigua */
        }
    }
    int idx = (libre >= 0) ? libre : victima;
    strncpy(t->s[idx].token, token, WEBAPI_TOKEN_LEN);
    t->s[idx].token[WEBAPI_TOKEN_LEN] = '\0';
    t->s[idx].expira = now + WEBAPI_SESSION_TTL_S;
    t->s[idx].en_uso = true;
}

void webapi_session_invalidate(webapi_sessions_t *t, const char *token)
{
    if (t == NULL || token == NULL) {
        return;
    }
    for (int i = 0; i < WEBAPI_SESSIONS; i++) {
        if (t->s[i].en_uso && ct_eq(t->s[i].token, token, WEBAPI_TOKEN_LEN)) {
            t->s[i].en_uso = false;
            return;
        }
    }
}

bool webapi_session_valid(webapi_sessions_t *t, const char *token, uint32_t now)
{
    if (t == NULL || token == NULL) {
        return false;
    }
    for (int i = 0; i < WEBAPI_SESSIONS; i++) {
        if (t->s[i].en_uso && ct_eq(t->s[i].token, token, WEBAPI_TOKEN_LEN)) {
            if (t->s[i].expira <= now) {
                t->s[i].en_uso = false; /* expirada: liberar */
                return false;
            }
            t->s[i].expira = now + WEBAPI_SESSION_TTL_S; /* refresca */
            return true;
        }
    }
    return false;
}

void webapi_nonces_init(webapi_nonces_t *t)
{
    if (t != NULL) {
        memset(t, 0, sizeof(*t));
    }
}

void webapi_nonce_issue(webapi_nonces_t *t, const char *nonce, uint32_t now)
{
    if (t == NULL || nonce == NULL) {
        return;
    }
    int libre = -1, victima = 0;
    for (int i = 0; i < WEBAPI_NONCES; i++) {
        if (!t->n[i].en_uso) {
            libre = i;
            break;
        }
        if (t->n[i].expira < t->n[victima].expira) {
            victima = i;
        }
    }
    int idx = (libre >= 0) ? libre : victima;
    strncpy(t->n[idx].nonce, nonce, WEBAPI_NONCE_LEN);
    t->n[idx].nonce[WEBAPI_NONCE_LEN] = '\0';
    t->n[idx].expira = now + WEBAPI_NONCE_TTL_S;
    t->n[idx].en_uso = true;
}

bool webapi_nonce_take(webapi_nonces_t *t, const char *nonce, uint32_t now)
{
    if (t == NULL || nonce == NULL) {
        return false;
    }
    for (int i = 0; i < WEBAPI_NONCES; i++) {
        if (t->n[i].en_uso && ct_eq(t->n[i].nonce, nonce, WEBAPI_NONCE_LEN)) {
            bool vigente = t->n[i].expira > now;
            t->n[i].en_uso = false; /* un solo uso: se consume aunque haya expirado */
            return vigente;
        }
    }
    return false;
}

bool webapi_verify_challenge(const uint8_t h[32], const char *nonce,
                             const char *resp_hex, webapi_hmac_fn hmac)
{
    if (h == NULL || nonce == NULL || resp_hex == NULL || hmac == NULL) {
        return false;
    }
    if (strnlen(resp_hex, 65) != 64) {
        return false; /* debe ser exactamente 32 bytes en hex */
    }
    uint8_t mac[32];
    hmac(h, 32, (const uint8_t *)nonce, strlen(nonce), mac);
    static const char HEX[] = "0123456789abcdef";
    char esperado[65];
    for (int i = 0; i < 32; i++) {
        esperado[i * 2] = HEX[mac[i] >> 4];
        esperado[i * 2 + 1] = HEX[mac[i] & 0xF];
    }
    esperado[64] = '\0';
    /* comparación en tiempo constante (acepta hex en mayúsc. o minúsc.) */
    uint8_t diff = 0;
    for (int i = 0; i < 64; i++) {
        char c = resp_hex[i];
        if (c >= 'A' && c <= 'F') {
            c = (char)(c - 'A' + 'a');
        }
        diff |= (uint8_t)(c ^ esperado[i]);
    }
    return diff == 0;
}
