/* clients — registro por cliente (IP) de actividad DNS (PURO). Ver clients.h. */
#include "clients.h"

#include <string.h>

/* Igualdad de IP: mismo family y mismos 16 bytes (los no usados están a cero). */
static bool ip_eq(const ip_addr16_t *a, const ip_addr16_t *b)
{
    return a->family == b->family && memcmp(a->bytes, b->bytes, 16) == 0;
}

void clients_init(clients_t *c)
{
    memset(c, 0, sizeof(*c));
}

void clients_record(clients_t *c, const ip_addr16_t *ip, bool blocked, uint32_t now_s)
{
    int libre = -1;         /* primer hueco */
    int lru = -1;           /* entrada en uso vista hace más tiempo */
    uint32_t lru_visto = 0;

    for (int i = 0; i < CLIENTS_TABLE; i++) {
        client_ent_t *e = &c->e[i];
        if (e->en_uso && ip_eq(&e->ip, ip)) {
            e->total++;
            if (blocked) {
                e->blocked++;
            }
            e->visto_s = now_s;
            return; /* cliente existente actualizado */
        }
        if (!e->en_uso) {
            if (libre < 0) {
                libre = i;
            }
        } else if (lru < 0 || e->visto_s < lru_visto) {
            lru = i;
            lru_visto = e->visto_s;
        }
    }

    /* IP nueva: usa un hueco o desaloja la vista hace más tiempo (LRU). */
    int idx = (libre >= 0) ? libre : lru;
    client_ent_t *e = &c->e[idx];
    e->ip = *ip;
    e->total = 1;
    e->blocked = blocked ? 1 : 0;
    e->visto_s = now_s;
    e->en_uso = true;
}

size_t clients_snapshot(const clients_t *c, client_ent_t *out, size_t cap)
{
    size_t n = 0;
    for (int i = 0; i < CLIENTS_TABLE && n < cap; i++) {
        if (c->e[i].en_uso) {
            out[n++] = c->e[i];
        }
    }
    return n;
}

void clients_reset(clients_t *c)
{
    clients_init(c);
}
