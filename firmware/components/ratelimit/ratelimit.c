#include "ratelimit.h"

#include <string.h>

void ratelimit_init(ratelimit_t *rl, uint16_t ip_rate, uint16_t ip_burst,
                    uint16_t glob_rate, uint16_t glob_burst)
{
    if (rl == NULL) {
        return;
    }
    memset(rl, 0, sizeof(*rl));
    rl->ip_rate = ip_rate;
    rl->ip_burst = ip_burst;
    rl->glob_rate = glob_rate;
    rl->glob_burst = glob_burst;
    rl->glob_tokens_mili = (uint32_t)glob_burst * 1000u;
}

/* recarga en mili-tokens: rate tokens/s con reloj en ms ⇒ rate × elapsed */
static void recarga(uint32_t *tokens_mili, uint32_t *ultimo_ms, uint16_t rate,
                    uint16_t burst, uint32_t now_ms)
{
    uint32_t transcurrido = now_ms - *ultimo_ms; /* wrap de u32 seguro */
    if (transcurrido == 0) {
        return;
    }
    uint32_t tope = (uint32_t)burst * 1000u;
    uint64_t nuevos = (uint64_t)*tokens_mili + (uint64_t)rate * transcurrido;
    *tokens_mili = (nuevos > tope) ? tope : (uint32_t)nuevos;
    *ultimo_ms = now_ms;
}

static bool misma_ip(const ip_addr16_t *a, const ip_addr16_t *b)
{
    return a->family == b->family &&
           memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

bool ratelimit_check(ratelimit_t *rl, const ip_addr16_t *client, uint32_t now_ms)
{
    if (rl == NULL || client == NULL) {
        return false;
    }
    /* techo global primero: sin presupuesto global no se admite nada */
    recarga(&rl->glob_tokens_mili, &rl->glob_ultimo_ms, rl->glob_rate,
            rl->glob_burst, now_ms);
    if (rl->glob_tokens_mili < 1000u) {
        return false;
    }

    /* búsqueda de la IP y del candidato de desalojo en una sola pasada
     * (tabla acotada, sin asignación) */
    rl_bucket_t *b = NULL;
    rl_bucket_t *victima = NULL;
    for (int i = 0; i < RATELIMIT_TABLE; i++) {
        rl_bucket_t *s = &rl->por_ip[i];
        if (s->en_uso && misma_ip(&s->ip, client)) {
            b = s;
            break;
        }
        if (victima == NULL) {
            victima = s;
        } else if (victima->en_uso &&
                   (!s->en_uso || (int32_t)(s->usado_ms - victima->usado_ms) < 0)) {
            victima = s; /* hueco libre, o en-uso más antiguo (LRU) */
        }
    }
    if (b == NULL) {
        b = victima;
        b->en_uso = true;
        b->ip = *client;
        b->tokens_mili = (uint32_t)rl->ip_burst * 1000u;
        b->ultimo_ms = now_ms;
    } else {
        recarga(&b->tokens_mili, &b->ultimo_ms, rl->ip_rate, rl->ip_burst, now_ms);
    }
    b->usado_ms = now_ms;

    if (b->tokens_mili < 1000u) {
        return false; /* la IP agotó su presupuesto; el global no se consume */
    }
    b->tokens_mili -= 1000u;
    rl->glob_tokens_mili -= 1000u;
    return true;
}
