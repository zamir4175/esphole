#include "metrics.h"

#include <stdatomic.h>

/* Estructura estática única: tamaño fijo conocido en compilación (P-VII). */
static struct {
    atomic_uint_least32_t contador[MET__COUNT];
    atomic_uint_least32_t upstream_fallos[METRICS_UPSTREAMS];
    atomic_uint_least32_t latencia_hist[METRICS_HIST_BUCKETS];
    atomic_uint_least32_t latencia_inline_max_us;
} m;

void metrics_init(void)
{
    for (int i = 0; i < MET__COUNT; i++) {
        atomic_store_explicit(&m.contador[i], 0, memory_order_relaxed);
    }
    for (int i = 0; i < METRICS_UPSTREAMS; i++) {
        atomic_store_explicit(&m.upstream_fallos[i], 0, memory_order_relaxed);
    }
    for (int i = 0; i < METRICS_HIST_BUCKETS; i++) {
        atomic_store_explicit(&m.latencia_hist[i], 0, memory_order_relaxed);
    }
    atomic_store_explicit(&m.latencia_inline_max_us, 0, memory_order_relaxed);
}

void metrics_inc(metric_t met)
{
    if (met < MET__COUNT) {
        atomic_fetch_add_explicit(&m.contador[met], 1, memory_order_relaxed);
    }
}

void metrics_upstream_fallo(uint8_t idx)
{
    if (idx < METRICS_UPSTREAMS) {
        atomic_fetch_add_explicit(&m.upstream_fallos[idx], 1,
                                  memory_order_relaxed);
    }
}

void metrics_latencia_ms(uint32_t ms)
{
    static const uint32_t limites[METRICS_HIST_BUCKETS - 1] = {1, 10, 50, 100, 500};
    int b = METRICS_HIST_BUCKETS - 1;
    for (int i = 0; i < METRICS_HIST_BUCKETS - 1; i++) {
        if (ms < limites[i]) {
            b = i;
            break;
        }
    }
    atomic_fetch_add_explicit(&m.latencia_hist[b], 1, memory_order_relaxed);
}

void metrics_latencia_inline_us(uint32_t us)
{
    uint32_t actual = atomic_load_explicit(&m.latencia_inline_max_us,
                                           memory_order_relaxed);
    while (us > actual &&
           !atomic_compare_exchange_weak_explicit(&m.latencia_inline_max_us,
                                                  &actual, us,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
        /* actual se recarga en cada intento fallido */
    }
}

void metrics_snapshot(metrics_snapshot_t *out)
{
    if (out == NULL) {
        return;
    }
    for (int i = 0; i < MET__COUNT; i++) {
        out->contador[i] =
            atomic_load_explicit(&m.contador[i], memory_order_relaxed);
    }
    for (int i = 0; i < METRICS_UPSTREAMS; i++) {
        out->upstream_fallos[i] =
            atomic_load_explicit(&m.upstream_fallos[i], memory_order_relaxed);
    }
    for (int i = 0; i < METRICS_HIST_BUCKETS; i++) {
        out->latencia_hist[i] =
            atomic_load_explicit(&m.latencia_hist[i], memory_order_relaxed);
    }
    out->latencia_inline_max_us =
        atomic_load_explicit(&m.latencia_inline_max_us, memory_order_relaxed);
}
