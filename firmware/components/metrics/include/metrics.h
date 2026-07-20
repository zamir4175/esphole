/*
 * metrics — contadores de servicio de tamaño fijo (FR-012, P-VII).
 * Estructura estática, incrementos atómicos (stdatomic: host y target),
 * cero asignación. El transporte (API HTTP) es de una spec futura; aquí
 * solo existen y son legibles vía snapshot.
 * Los contadores envuelven en uint32 (documentado): el consumidor calcula deltas.
 */
#ifndef ESPHOLE_METRICS_H
#define ESPHOLE_METRICS_H

#include "esphole_types.h"

#define METRICS_UPSTREAMS 4
#define METRICS_HIST_BUCKETS 6 /* <1, <10, <50, <100, <500, ≥500 ms */

typedef enum {
    MET_TOTAL = 0,       /* consultas recibidas válidas */
    MET_BLOQUEADAS,
    MET_CACHE_HITS,
    MET_REENVIADAS,
    MET_SERVFAIL,
    MET_MALFORMADAS,     /* descartadas por formato (FR-009) */
    MET_RATELIMITED,     /* descartadas por tasa (FR-010) */
    MET_NO_LOCALES,      /* ignoradas por origen no local (R6) */
    MET_BLOCKLIST_TRUNC,
    MET_CACHE_EVICTIONS,
    MET_PENDING_OVERFLOW,
    MET__COUNT
} metric_t;

typedef struct {
    uint32_t contador[MET__COUNT];
    uint32_t upstream_fallos[METRICS_UPSTREAMS];
    uint32_t latencia_hist[METRICS_HIST_BUCKETS];
    uint32_t latencia_inline_max_us; /* peor caso del camino rápido (FR-013) */
} metrics_snapshot_t;

void metrics_init(void); /* pone todo a cero */
void metrics_inc(metric_t m);
void metrics_upstream_fallo(uint8_t idx);
void metrics_latencia_ms(uint32_t ms);        /* clasifica en el histograma */
void metrics_latencia_inline_us(uint32_t us); /* conserva el máximo */
void metrics_snapshot(metrics_snapshot_t *out);

#endif /* ESPHOLE_METRICS_H */
