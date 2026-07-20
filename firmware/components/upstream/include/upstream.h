/*
 * upstream — reenvío al resolvedor upstream con failover consciente de salud
 * (FR-008/FR-011, R5). Refinamiento de diseño sobre el plan: en vez de una
 * tarea con colas y locks, usa un segundo pcb raw de lwIP y ejecuta TODO en
 * el hilo tcpip (submit desde el callback del listener; respuestas en su
 * propio callback; timeouts entrando por tcpip_callback desde un esp_timer).
 * Ruta DNS 100% single-threaded: cero carreras y cero latencia de cola.
 */
#ifndef ESPHOLE_UPSTREAM_H
#define ESPHOLE_UPSTREAM_H

#include "cache.h"
#include "config_nvs.h"
#include "esphole_types.h"

/* Timeout por intento (data-model §5): 1 reintento al siguiente sano. */
#define UPSTREAM_TIMEOUT_MS 1500

/* Crea el pcb, el timer de expiración y se registra como forward de net_dns.
 * cfg y cache deben vivir para siempre. */
bool upstream_start(const esphole_config_t *cfg, cache_t *cache);

/* Salud por upstream para la API (spec 003): 0=sano, 1=sospechoso, 2=caído.
 * 'count' recibe los upstreams configurados. Lectura de monitoreo. */
void upstream_health(uint8_t salud[CONFIG_UPSTREAMS_MAX], uint8_t *count);

#endif /* ESPHOLE_UPSTREAM_H */
