#include "hostlist.h"

/* Réplica on-device de la extracción de tools/gen_blocklist.py. Sin ESP-IDF. */

static bool es_blanco(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static char a_min(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

/* ¿[d, d+dl) es igual (sin distinguir mayúsculas) al literal NUL-terminado? */
static bool ci_igual(const char *d, size_t dl, const char *lit)
{
    size_t i = 0;
    for (; i < dl; i++) {
        if (lit[i] == '\0' || a_min(d[i]) != a_min(lit[i])) {
            return false;
        }
    }
    return lit[i] == '\0'; /* misma longitud */
}

/* Pseudo-dominios de sistema que nunca se bloquean (como el set EXCLUIR del
 * generador). */
static bool es_excluido(const char *d, size_t dl)
{
    static const char *const EXCL[] = {
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    };
    for (size_t i = 0; i < sizeof(EXCL) / sizeof(EXCL[0]); i++) {
        if (ci_igual(d, dl, EXCL[i])) {
            return true;
        }
    }
    return false;
}

bool hostlist_parse_line(const char *line, size_t len, const char **dom,
                         size_t *dom_len)
{
    if (line == NULL || len == 0 || dom == NULL || dom_len == NULL) {
        return false;
    }
    /* 1. recorta el comentario desde el primer '#' */
    size_t end = len;
    for (size_t i = 0; i < end; i++) {
        if (line[i] == '#') {
            end = i;
            break;
        }
    }
    /* 2. recorta blancos al inicio y al final */
    size_t s = 0;
    while (s < end && es_blanco(line[s])) {
        s++;
    }
    while (end > s && es_blanco(line[end - 1])) {
        end--;
    }
    if (s >= end) {
        return false; /* vacía o solo comentario/blancos */
    }
    /* 3. primer campo [s, t1e) */
    size_t t1e = s;
    while (t1e < end && !es_blanco(line[t1e])) {
        t1e++;
    }
    /* ¿hay un segundo campo? */
    size_t t2s = t1e;
    while (t2s < end && es_blanco(line[t2s])) {
        t2s++;
    }
    const char *d;
    size_t dl;
    if (t2s < end) {
        /* formato HOSTS "IP dominio": el dominio es el 2º campo */
        size_t t2e = t2s;
        while (t2e < end && !es_blanco(line[t2e])) {
            t2e++;
        }
        d = line + t2s;
        dl = t2e - t2s;
    } else {
        /* lista plana: el único campo es el dominio */
        d = line + s;
        dl = t1e - s;
    }
    /* 4. exclusión de pseudo-dominios de sistema */
    if (es_excluido(d, dl)) {
        return false;
    }
    *dom = d;
    *dom_len = dl;
    return true;
}
