/*
 * ratelimit — token-bucket por IP (tabla fija LRU) + techo global (PURO).
 * Contrato: specs/001-servicio-dns-core/contracts/module-interfaces.md §5.
 * Reloj inyectado en ms monotónicos. Las malformadas se descartan ANTES de
 * llamar aquí (no consumen tokens, R6).
 */
#ifndef ESPHOLE_RATELIMIT_H
#define ESPHOLE_RATELIMIT_H

#include "esphole_types.h"

#define RATELIMIT_TABLE 64 /* buckets por IP simultáneos (desalojo LRU) */

typedef struct {
    ip_addr16_t ip;
    uint32_t tokens_mili; /* tokens ×1000 (recarga con resto exacto) */
    uint32_t ultimo_ms;   /* última recarga */
    uint32_t usado_ms;    /* último uso, para LRU */
    bool en_uso;
} rl_bucket_t;

typedef struct {
    uint16_t ip_rate, ip_burst;     /* consultas/s y ráfaga por IP */
    uint16_t glob_rate, glob_burst; /* techo global */
    rl_bucket_t por_ip[RATELIMIT_TABLE];
    uint32_t glob_tokens_mili;
    uint32_t glob_ultimo_ms;
} ratelimit_t;

void ratelimit_init(ratelimit_t *rl, uint16_t ip_rate, uint16_t ip_burst,
                    uint16_t glob_rate, uint16_t glob_burst);

/* true = admitir; false = descartar en silencio (CB-42/43). */
bool ratelimit_check(ratelimit_t *rl, const ip_addr16_t *client, uint32_t now_ms);

#endif /* ESPHOLE_RATELIMIT_H */
