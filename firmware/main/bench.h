#ifndef ESPHOLE_BENCH_H
#define ESPHOLE_BENCH_H

#include "blocklist.h"

/* Mediciones de cota on-target (T029/CB-60/62). Genera 200k dominios
 * sintéticos en 'bl' (usa la estructura ya reservada; NO cargar la lista real
 * en modo bench), mide el peor caso de lookup sobre PSRAM y reporta por serial.
 * El build de producción no la llama (guardada por CONFIG_ESPHOLE_BENCH). */
void bench_run(blocklist_t *bl);

#endif /* ESPHOLE_BENCH_H */
