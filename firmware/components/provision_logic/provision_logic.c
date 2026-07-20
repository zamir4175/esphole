#include "provision_logic.h"

#include <string.h>

/* hex → valor, o -1 si no es dígito hex */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/*
 * Decodifica un valor form-urlencoded [ini, fin) en out (tope out_cap incluido
 * el NUL). Devuelve 0 ok, -1 %XX inválido, 1 demasiado largo.
 */
static int url_decode(const char *ini, const char *fin, char *out, size_t out_cap)
{
    size_t w = 0;
    for (const char *p = ini; p < fin; p++) {
        char c;
        if (*p == '+') {
            c = ' ';
        } else if (*p == '%') {
            if (p + 2 >= fin) {
                return -1; /* %X truncado: faltan los dos dígitos hex */
            }
            int hi = hexval(p[1]);
            int lo = hexval(p[2]);
            if (hi < 0 || lo < 0) {
                return -1;
            }
            c = (char)((hi << 4) | lo);
            p += 2;
        } else {
            c = *p;
        }
        if (w + 1 >= out_cap) {
            return 1; /* no cabe con el NUL */
        }
        out[w++] = c;
    }
    out[w] = '\0';
    return 0;
}

prov_form_err_t provision_form_parse(const char *body, size_t len,
                                     prov_creds_t *out)
{
    if (body == NULL || out == NULL) {
        return PROV_FORM_MALFORMED;
    }
    memset(out, 0, sizeof(*out));
    bool tiene_ssid = false;
    bool tiene_pass = false;

    const char *p = body;
    const char *end = body + len;
    while (p < end) {
        /* clave hasta '=' */
        const char *eq = memchr(p, '=', (size_t)(end - p));
        if (eq == NULL) {
            break; /* par sin '=': fin útil */
        }
        const char *amp = memchr(eq + 1, '&', (size_t)(end - (eq + 1)));
        const char *val_fin = (amp != NULL) ? amp : end;
        size_t klen = (size_t)(eq - p);

        if (klen == 4 && memcmp(p, "ssid", 4) == 0) {
            int r = url_decode(eq + 1, val_fin, out->ssid, sizeof(out->ssid));
            if (r == 1) {
                return PROV_FORM_TOO_LONG;
            }
            if (r < 0) {
                return PROV_FORM_MALFORMED;
            }
            tiene_ssid = true;
        } else if (klen == 4 && memcmp(p, "pass", 4) == 0) {
            int r = url_decode(eq + 1, val_fin, out->pass, sizeof(out->pass));
            if (r == 1) {
                return PROV_FORM_TOO_LONG;
            }
            if (r < 0) {
                return PROV_FORM_MALFORMED;
            }
            tiene_pass = true;
        }
        /* otras claves: ignoradas */

        if (amp == NULL) {
            break;
        }
        p = amp + 1;
    }
    (void)tiene_pass; /* pass ausente ⇒ cadena vacía = red abierta */
    return tiene_ssid ? PROV_FORM_OK : PROV_FORM_MALFORMED;
}

bool provision_creds_valid(const prov_creds_t *c)
{
    if (c == NULL) {
        return false;
    }
    size_t sl = strnlen(c->ssid, sizeof(c->ssid));
    size_t pl = strnlen(c->pass, sizeof(c->pass));
    if (sl < 1 || sl > PROV_SSID_MAX) {
        return false;
    }
    for (size_t i = 0; i < sl; i++) {
        if ((uint8_t)c->ssid[i] < 0x20) {
            return false; /* control chars en SSID */
        }
    }
    if (pl != 0 && (pl < 8 || pl > 63)) {
        return false; /* pass: vacío (abierto) o 8..63 (WPA2) */
    }
    return true;
}

void provision_ap_ssid(const uint8_t mac[6], char *out_ssid)
{
    static const char HEX[] = "0123456789ABCDEF";
    if (out_ssid == NULL || mac == NULL) {
        return;
    }
    memcpy(out_ssid, "ESPHole-", 8);
    out_ssid[8] = HEX[(mac[4] >> 4) & 0xF];
    out_ssid[9] = HEX[mac[4] & 0xF];
    out_ssid[10] = HEX[(mac[5] >> 4) & 0xF];
    out_ssid[11] = HEX[mac[5] & 0xF];
    out_ssid[12] = '\0';
}

void provision_ap_pass(const uint8_t rand_bytes[8], char *out_pass)
{
    if (out_pass == NULL || rand_bytes == NULL) {
        return;
    }
    /* 8 bytes aleatorios (64 bits del RNG hardware) → 10 chars imprimibles del
     * rango [33,126] (94 valores ≈ 6.55 bits/char, ~65 bits de entropía). La
     * clave es un secreto real, no derivable de valores públicos (Principio V). */
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | rand_bytes[i];
    }
    for (int i = 0; i < 10; i++) {
        out_pass[i] = (char)(33 + (v % 94));
        v /= 94;
    }
    out_pass[10] = '\0';
}

prov_mode_t provision_decide_boot(bool has_creds, bool provisioned,
                                  bool boot_held)
{
    (void)provisioned; /* no afecta el arranque; el fallback lo gestiona el HW */
    if (boot_held || !has_creds) {
        return PROV_MODE_PROVISION;
    }
    return PROV_MODE_CONNECTING;
}
