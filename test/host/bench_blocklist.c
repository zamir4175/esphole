/*
 * T012 — micro-benchmark de blocklist en host: 200 k dominios sintéticos,
 * 100 k lookups. Solo orientativo (línea base para comparar): la cota real
 * de <100 µs se mide on-target sobre PSRAM (T029 / CB-60).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blocklist.h"

#define N_DOMINIOS 200000
#define N_LOOKUPS  100000
#define BLOB_CAP   (6u * 1024 * 1024)

static uint64_t ns_ahora(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* xorshift32: generador determinista, mismo stream en cada ejecución */
static uint32_t rnd_state = 0x12345678;
static uint32_t rnd(void)
{
    uint32_t x = rnd_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return rnd_state = x;
}

static size_t dominio_sintetico(uint32_t i, char *out)
{
    static const char *tld[] = {"com", "net", "org", "io", "tv"};
    return (size_t)sprintf(out, "%s.dominio%07u.ads%u", tld[i % 5], i, i % 97);
}

int main(void)
{
    char *blob = malloc(BLOB_CAP);
    uint32_t *idx = malloc(N_DOMINIOS * sizeof(uint32_t));
    if (blob == NULL || idx == NULL) {
        fprintf(stderr, "sin memoria\n");
        return 1;
    }

    blocklist_t bl;
    blocklist_init(&bl, blob, BLOB_CAP, idx, N_DOMINIOS);

    char nombre[ESPHOLE_DOMAIN_MAX + 1];
    for (uint32_t i = 0; i < N_DOMINIOS; i++) {
        size_t len = dominio_sintetico(i, nombre);
        if (!blocklist_add(&bl, nombre, len)) {
            fprintf(stderr, "add falló en %u (truncated=%u)\n", i, bl.truncated);
            return 1;
        }
    }

    uint64_t t0 = ns_ahora();
    blocklist_finalize(&bl);
    uint64_t t_sort = ns_ahora() - t0;
    printf("carga: %u entradas, blob %.1f MB, sort+dedupe %.0f ms\n", bl.count,
           bl.blob_len / 1048576.0, t_sort / 1e6);

    /* mitad hits (subdominios de entradas), mitad misses */
    uint32_t hits = 0;
    t0 = ns_ahora();
    for (uint32_t i = 0; i < N_LOOKUPS; i++) {
        size_t len;
        if (rnd() & 1) {
            len = dominio_sintetico(rnd() % N_DOMINIOS, nombre);
            len += (size_t)sprintf(nombre + len, ".sub%u", rnd() % 100);
        } else {
            len = (size_t)sprintf(nombre, "com.inexistente%07u.x", rnd());
        }
        if (blocklist_contains(&bl, nombre, len)) {
            hits++;
        }
    }
    uint64_t t_total = ns_ahora() - t0;

    printf("lookups: %u (hits %u), media %.0f ns/lookup\n", N_LOOKUPS, hits,
           (double)t_total / N_LOOKUPS);

    /* cordura: los hits deben ser ~50% */
    if (hits < N_LOOKUPS / 3 || hits > 2 * N_LOOKUPS / 3) {
        fprintf(stderr, "distribución de hits sospechosa\n");
        return 1;
    }
    free(blob);
    free(idx);
    return 0;
}
