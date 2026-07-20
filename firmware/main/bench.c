/*
 * Medición de cotas on-target (T029).
 * CB-60: peor caso de blocklist_contains con 200k entradas en PSRAM < 100 µs.
 * CB-62: heap interno libre ≥ 48 KB tras cargar la estructura.
 * Mide lookups individuales con el contador de ciclos de CPU (precisión de
 * ciclo; esp_timer solo da 1 µs y un lookup ronda esa escala).
 */
#include "bench.h"

#include <stdio.h>
#include <string.h>

#include "esp_cpu.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "bench";

#define N_DOM 200000u
#define N_LOOKUPS 100000u
#define CPU_MHZ 240u /* CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240 */

/* xorshift32 determinista: mismo stream en cada arranque */
static uint32_t s_rng = 0x9e3779b9u;
static uint32_t rng(void)
{
    uint32_t x = s_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return s_rng = x;
}

/* dominio invertido sintético: "com.domNNNNNNN" (para add y para hit-base) */
static size_t sintetico(uint32_t i, char *out)
{
    static const char *tld[] = {"com", "net", "org", "io", "tv"};
    return (size_t)sprintf(out, "%s.dom%07u", tld[i % 5], (unsigned)i);
}

void bench_run(blocklist_t *bl)
{
    char nombre[ESPHOLE_DOMAIN_MAX + 1];

    ESP_LOGW(TAG, "=== BENCH T029: cargando %u dominios sintéticos ===", N_DOM);
    int64_t t0 = esp_timer_get_time();
    uint32_t añadidos = 0;
    for (uint32_t i = 0; i < N_DOM; i++) {
        size_t n = sintetico(i, nombre);
        if (blocklist_add(bl, nombre, n)) {
            añadidos++;
        }
    }
    blocklist_finalize(bl);
    int64_t t_carga = esp_timer_get_time() - t0;
    ESP_LOGW(TAG, "carga: %u añadidos, %u activos, truncados %u, %lld ms",
             añadidos, (unsigned)bl->count, (unsigned)bl->truncated,
             t_carga / 1000);

    /* --- CB-60: peor caso de lookup en PSRAM --- */
    uint32_t peor_ciclos = 0;
    uint64_t suma_ciclos = 0;
    uint32_t hits = 0;
    for (uint32_t k = 0; k < N_LOOKUPS; k++) {
        size_t len;
        bool espera_hit = (rng() & 1) != 0;
        if (espera_hit) {
            /* subdominio de una entrada existente: recorre TODA la búsqueda
             * de prefijos hasta encontrar la coincidencia (peor caso real) */
            uint32_t base = rng() % bl->count;
            len = sintetico(base, nombre);
            len += (size_t)sprintf(nombre + len, ".s%u", (unsigned)(rng() % 1000));
        } else {
            len = (size_t)sprintf(nombre, "com.zzzmiss%07u", (unsigned)rng());
        }
        uint32_t c0 = esp_cpu_get_cycle_count();
        bool r = blocklist_contains(bl, nombre, len);
        uint32_t dc = esp_cpu_get_cycle_count() - c0;
        if (r) {
            hits++;
        }
        suma_ciclos += dc;
        if (dc > peor_ciclos) {
            peor_ciclos = dc;
        }
    }
    uint32_t peor_us = peor_ciclos / CPU_MHZ;
    uint32_t peor_ns = (uint32_t)((uint64_t)peor_ciclos * 1000 / CPU_MHZ);
    uint32_t media_ns = (uint32_t)(suma_ciclos * 1000 / CPU_MHZ / N_LOOKUPS);

    ESP_LOGW(TAG, "lookups (con preempción): %u (hits %u)", N_LOOKUPS, hits);
    ESP_LOGW(TAG, "  media  : %u ns/lookup", (unsigned)media_ns);
    ESP_LOGW(TAG, "  peor   : %u ns (%u µs) — incluye jitter del scheduler",
             (unsigned)peor_ns, (unsigned)peor_us);

    /* Peor caso ALGORÍTMICO limpio: cada lookup en sección crítica corta
     * (sin preempción de Wi-Fi/timers). Es el coste real de la estructura,
     * que es lo que acota la constitución (FR-013/CB-60). */
    portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
    uint32_t peor_limpio = 0;
    for (uint32_t k = 0; k < 20000; k++) {
        size_t len;
        if (rng() & 1) {
            uint32_t base = rng() % bl->count;
            len = sintetico(base, nombre);
            len += (size_t)sprintf(nombre + len, ".s%u", (unsigned)(rng() % 1000));
        } else {
            len = (size_t)sprintf(nombre, "com.zzzmiss%07u", (unsigned)rng());
        }
        taskENTER_CRITICAL(&mux);
        uint32_t c0 = esp_cpu_get_cycle_count();
        volatile bool r = blocklist_contains(bl, nombre, len);
        uint32_t dc = esp_cpu_get_cycle_count() - c0;
        taskEXIT_CRITICAL(&mux);
        (void)r;
        if (dc > peor_limpio) {
            peor_limpio = dc;
        }
    }
    uint32_t limpio_us = peor_limpio / CPU_MHZ;
    ESP_LOGW(TAG, "  PEOR limpio (sin preempción): %u ns (%u µs, %u ciclos)",
             (unsigned)((uint64_t)peor_limpio * 1000 / CPU_MHZ),
             (unsigned)limpio_us, (unsigned)peor_limpio);
    ESP_LOGW(TAG, "  CB-60 (<100 µs, coste algorítmico): %s",
             limpio_us < 100 ? "PASA ✓" : "FALLA ✗");

    /* --- CB-62: presupuesto de memoria --- */
    size_t heap_int = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t heap_int_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    size_t psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    ESP_LOGW(TAG, "heap interno: %u B libre (mínimo histórico %u B); PSRAM %u B",
             (unsigned)heap_int, (unsigned)heap_int_min, (unsigned)psram);
    ESP_LOGW(TAG, "  CB-62 (heap ≥48 KB): %s",
             heap_int_min >= 48 * 1024 ? "PASA ✓" : "FALLA ✗");

    /* Marcas de agua de pila (CB-62). Sin CONFIG_FREERTOS_USE_TRACE_FACILITY
     * no se puede enumerar todas las tareas; se reportan por handle las de la
     * ruta DNS accesibles: la del hilo tcpip (donde corre el camino rápido) y
     * la tarea TCP. El presupuesto del plan es ≤32 KB de pila en total. */
    TaskHandle_t tcpip = xTaskGetHandle("tcpip_task");
    TaskHandle_t tcp = xTaskGetHandle("tcp_dns");
    if (tcpip != NULL) {
        ESP_LOGW(TAG, "  pila tcpip_task: %u B libres (mín histórico)",
                 (unsigned)(uxTaskGetStackHighWaterMark(tcpip) * sizeof(StackType_t)));
    }
    if (tcp != NULL) {
        ESP_LOGW(TAG, "  pila tcp_dns: %u B libres (mín histórico)",
                 (unsigned)(uxTaskGetStackHighWaterMark(tcp) * sizeof(StackType_t)));
    }
    ESP_LOGW(TAG, "  pila main (esta tarea): %u B libres",
             (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));

    ESP_LOGW(TAG, "=== BENCH fin (el dispositivo sigue sirviendo con estos "
                  "200k dominios sintéticos) ===");
}
