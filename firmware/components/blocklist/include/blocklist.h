/*
 * blocklist — store de dominios invertidos ordenados + búsqueda binaria (PURO).
 * Contrato: specs/001-servicio-dns-core/contracts/module-interfaces.md §3.
 * Fail-open: contains() con estado ≠ ACTIVE devuelve SIEMPRE false (FR-007).
 * Memoria del llamador; truncado determinista y observable al llegar al tope.
 */
#ifndef ESPHOLE_BLOCKLIST_H
#define ESPHOLE_BLOCKLIST_H

#include "esphole_types.h"

typedef enum { BL_EMPTY = 0, BL_LOADING, BL_ACTIVE } blocklist_state_t;

typedef struct {
    char *blob;          /* dominios invertidos NUL-terminados, concatenados */
    uint32_t blob_cap;
    uint32_t blob_len;
    uint32_t *index;     /* offset de cada entrada en el blob */
    uint32_t index_cap;  /* en entradas */
    uint32_t count;
    blocklist_state_t state;
    uint32_t truncated;  /* entradas descartadas por tope (P-II, observable) */
} blocklist_t;

void blocklist_init(blocklist_t *bl, char *blob_mem, uint32_t blob_cap,
                    uint32_t *index_mem, uint32_t index_cap);

/*
 * Añade un dominio YA normalizado-invertido (salida de domain_normalize_invert).
 * false si no cabe (truncated++) o la entrada es inválida. Pasa a LOADING.
 */
bool blocklist_add(blocklist_t *bl, const char *inverted, size_t len);

/* Ordena, deduplica y activa. */
void blocklist_finalize(blocklist_t *bl);

/*
 * Vacía la lista conservando los buffers (blob/index/caps) para reutilizarla
 * (spec 004, actualización en caliente). Deja count/blob_len/truncated=0 y
 * state=EMPTY. No toca la memoria del llamador.
 */
void blocklist_reset(blocklist_t *bl);

/*
 * Serializa la lista finalizada al formato de partición EBL1
 * ("EBL1" | count u32 LE | entradas invertidas NUL-terminadas, en orden
 * lexicográfico) en buf. Devuelve los bytes escritos, o 0 si no cabe en cap.
 * (spec 004, persistencia on-device.)
 */
size_t blocklist_serialize(const blocklist_t *bl, uint8_t *buf, size_t cap);

/*
 * ¿'inverted' (nombre de consulta invertido) casa con alguna entrada por
 * sufijo consciente de etiquetas? Cota: <100 µs con 200 k entradas (CB-60).
 */
bool blocklist_contains(const blocklist_t *bl, const char *inverted, size_t len);

#endif /* ESPHOLE_BLOCKLIST_H */
