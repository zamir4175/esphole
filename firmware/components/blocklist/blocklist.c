#include "blocklist.h"

#include <string.h>

void blocklist_init(blocklist_t *bl, char *blob_mem, uint32_t blob_cap,
                    uint32_t *index_mem, uint32_t index_cap)
{
    if (bl == NULL) {
        return;
    }
    bl->blob = blob_mem;
    bl->blob_cap = blob_cap;
    bl->blob_len = 0;
    bl->index = index_mem;
    bl->index_cap = index_cap;
    bl->count = 0;
    bl->state = BL_EMPTY;
    bl->truncated = 0;
}

bool blocklist_add(blocklist_t *bl, const char *inverted, size_t len)
{
    if (bl == NULL || bl->blob == NULL || bl->index == NULL) {
        return false;
    }
    if (inverted == NULL || len == 0 || len > ESPHOLE_DOMAIN_MAX) {
        return false; /* entrada inválida: no cuenta como truncado */
    }
    bl->state = BL_LOADING;
    if (bl->count >= bl->index_cap || bl->blob_len + len + 1 > bl->blob_cap) {
        bl->truncated++; /* tope alcanzado: truncado determinista (P-II) */
        return false;
    }
    memcpy(bl->blob + bl->blob_len, inverted, len);
    bl->blob[bl->blob_len + len] = '\0';
    bl->index[bl->count++] = bl->blob_len;
    bl->blob_len += (uint32_t)len + 1;
    return true;
}

/* heapsort del índice por orden lexicográfico de sus entradas: O(n log n),
 * sin recursión ni memoria extra (200 k entradas en la pila sería inviable) */
static void sift_down(uint32_t *idx, uint32_t n, uint32_t root, const char *blob)
{
    for (;;) {
        uint32_t hijo = 2 * root + 1;
        if (hijo >= n) {
            return;
        }
        if (hijo + 1 < n && strcmp(blob + idx[hijo], blob + idx[hijo + 1]) < 0) {
            hijo++;
        }
        if (strcmp(blob + idx[root], blob + idx[hijo]) >= 0) {
            return;
        }
        uint32_t tmp = idx[root];
        idx[root] = idx[hijo];
        idx[hijo] = tmp;
        root = hijo;
    }
}

void blocklist_finalize(blocklist_t *bl)
{
    if (bl == NULL || bl->blob == NULL || bl->index == NULL) {
        return;
    }
    uint32_t n = bl->count;
    /* la carga desde partición llega ya ordenada (tools/gen_blocklist.py):
     * verificación O(n) y solo se ordena si hace falta */
    bool ordenada = true;
    for (uint32_t i = 1; i < n; i++) {
        if (strcmp(bl->blob + bl->index[i - 1], bl->blob + bl->index[i]) > 0) {
            ordenada = false;
            break;
        }
    }
    if (!ordenada) {
        for (uint32_t i = n / 2; i-- > 0;) {
            sift_down(bl->index, n, i, bl->blob);
        }
        for (uint32_t end = n; end > 1;) {
            end--;
            uint32_t tmp = bl->index[0];
            bl->index[0] = bl->index[end];
            bl->index[end] = tmp;
            sift_down(bl->index, end, 0, bl->blob);
        }
    }
    /* dedupe in situ sobre el índice ordenado */
    if (n > 1) {
        uint32_t w = 1;
        for (uint32_t i = 1; i < n; i++) {
            if (strcmp(bl->blob + bl->index[i], bl->blob + bl->index[w - 1]) != 0) {
                bl->index[w++] = bl->index[i];
            }
        }
        bl->count = w;
    }
    bl->state = BL_ACTIVE;
}

void blocklist_reset(blocklist_t *bl)
{
    if (bl == NULL) {
        return;
    }
    /* conserva blob/index/caps; solo reinicia el contenido lógico */
    bl->blob_len = 0;
    bl->count = 0;
    bl->truncated = 0;
    bl->state = BL_EMPTY;
}

size_t blocklist_serialize(const blocklist_t *bl, uint8_t *buf, size_t cap)
{
    if (bl == NULL || bl->blob == NULL || bl->index == NULL || buf == NULL) {
        return 0;
    }
    if (cap < 8) {
        return 0; /* ni siquiera la cabecera */
    }
    memcpy(buf, "EBL1", 4);
    uint32_t count = bl->count;
    buf[4] = (uint8_t)(count & 0xff);
    buf[5] = (uint8_t)((count >> 8) & 0xff);
    buf[6] = (uint8_t)((count >> 16) & 0xff);
    buf[7] = (uint8_t)((count >> 24) & 0xff);
    size_t w = 8;
    /* recorre el índice ORDENADO (finalize lo dejó lexicográfico) */
    for (uint32_t i = 0; i < count; i++) {
        const char *e = bl->blob + bl->index[i];
        size_t l = strlen(e);
        if (w + l + 1 > cap) {
            return 0; /* no cabe: el llamador amplía el buffer/partición */
        }
        memcpy(buf + w, e, l);
        buf[w + l] = '\0';
        w += l + 1;
    }
    return w;
}

/*
 * Un paso de búsqueda sobre el prefijo q[0..plen). Devuelve:
 *   1  = hay coincidencia por sufijo (q[0..plen) es una entrada, o el
 *        predecesor es prefijo de q en límite de etiqueta)
 *   0  = sin coincidencia a esta longitud; *next < plen es el siguiente
 *        prefijo a probar (el mayor candidato posible, derivado del LCP con
 *        el predecesor — inmune a la trampa del predecesor)
 *  -1  = descartado: no hay ninguna entrada prefijo de q
 *
 * Coste: UNA búsqueda binaria. Como cada paso salta directo al prefijo común,
 * un lookup real hace 1–2 pasos en vez de uno por etiqueta (menos accesos
 * aleatorios a PSRAM, que es el coste dominante — research.md R2).
 */
static int busca_paso(const blocklist_t *bl, const char *q, size_t plen,
                      size_t *next)
{
    uint32_t lo = 0;
    uint32_t hi = bl->count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const char *e = bl->blob + bl->index[mid];
        int cmp = strncmp(e, q, plen);
        if (cmp == 0) {
            if (e[plen] == '\0') {
                return 1; /* entrada == q[0..plen): coincidencia exacta */
            }
            cmp = 1; /* e coincide en plen pero sigue: e > q */
        }
        if (cmp < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return -1; /* nada ≤ q[0..plen) */
    }
    const char *pred = bl->blob + bl->index[lo - 1];
    /* LCP crudo del predecesor con q[0..plen) */
    size_t c = 0;
    while (c < plen && pred[c] != '\0' && pred[c] == q[c]) {
        c++;
    }
    /* ¿el predecesor es prefijo de q en límite de etiqueta? → coincidencia */
    if (pred[c] == '\0' && (c == plen || q[c] == '.')) {
        return 1;
    }
    /* siguiente candidato: mayor P ≤ c con q[P]=='.' (prefijo en límite) */
    size_t p = c;
    while (p > 0 && q[p] != '.') {
        p--;
    }
    if (p == 0) {
        return -1;
    }
    *next = p; /* q[p]=='.', prefijo q[0..p) de longitud p < plen */
    return 0;
}

bool blocklist_contains(const blocklist_t *bl, const char *inverted, size_t len)
{
    if (bl == NULL || bl->state != BL_ACTIVE || bl->count == 0 ||
        inverted == NULL || len == 0) {
        return false; /* fail-open: sin lista ACTIVA jamás se bloquea (FR-007) */
    }
    size_t plen = len;
    /* límite defensivo: nunca más de una iteración por etiqueta */
    for (int iter = 0; iter <= ESPHOLE_DOMAIN_MAX / 2 + 1; iter++) {
        size_t next = 0;
        int r = busca_paso(bl, inverted, plen, &next);
        if (r == 1) {
            return true;
        }
        if (r < 0) {
            return false;
        }
        plen = next; /* estrictamente decreciente */
    }
    return false;
}
