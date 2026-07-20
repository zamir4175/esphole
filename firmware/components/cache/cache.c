#include "cache.h"

#include <string.h>

#include "dns_wire.h"

#define SLOT_NONE 0xFFFF
/* pasos de búsqueda de expiradas desde la cola LRU al desalojar (acotado) */
#define EVICT_SCAN 8

struct cache_slot {
    char qname[ESPHOLE_DOMAIN_MAX + 1];
    uint8_t qname_len;
    uint16_t qtype, qclass;
    uint32_t expiry;   /* instante monotónico (s) de caducidad */
    uint32_t inserted;
    uint16_t resp_len;
    uint16_t lru_prev, lru_next;
    uint16_t hash_next; /* encadenado de bucket; en la free-list, siguiente libre */
    uint8_t resp[ESPHOLE_RESP_MAX];
};

size_t cache_mem_size(uint16_t capacity)
{
    return (size_t)capacity * sizeof(struct cache_slot) +
           (size_t)capacity * sizeof(uint16_t);
}

void cache_init(cache_t *c, void *mem, uint16_t capacity, uint32_t ttl_cap)
{
    if (c == NULL || mem == NULL || capacity == 0) {
        return;
    }
    c->slots = (struct cache_slot *)mem;
    c->buckets = (uint16_t *)((uint8_t *)mem +
                              (size_t)capacity * sizeof(struct cache_slot));
    c->capacity = capacity;
    c->ttl_cap = ttl_cap;
    c->lru_head = SLOT_NONE;
    c->lru_tail = SLOT_NONE;
    c->evictions = 0;
    for (uint16_t i = 0; i < capacity; i++) {
        c->buckets[i] = SLOT_NONE;
        c->slots[i].hash_next = (uint16_t)(i + 1);
    }
    c->slots[capacity - 1].hash_next = SLOT_NONE;
    c->free_head = 0;
}

static uint32_t hash_key(const char *name, uint8_t len, uint16_t qtype,
                         uint16_t qclass)
{
    uint32_t h = 2166136261u; /* FNV-1a */
    for (uint8_t i = 0; i < len; i++) {
        h = (h ^ (uint8_t)name[i]) * 16777619u;
    }
    h = (h ^ qtype) * 16777619u;
    h = (h ^ qclass) * 16777619u;
    return h;
}

static uint16_t bucket_de(const cache_t *c, const dns_query_t *q)
{
    return (uint16_t)(hash_key(q->qname, q->qname_len, q->qtype, q->qclass) %
                      c->capacity);
}

static bool misma_clave(const struct cache_slot *s, const dns_query_t *q)
{
    return s->qname_len == q->qname_len && s->qtype == q->qtype &&
           s->qclass == q->qclass &&
           memcmp(s->qname, q->qname, q->qname_len) == 0;
}

static uint16_t busca(const cache_t *c, const dns_query_t *q)
{
    for (uint16_t i = c->buckets[bucket_de(c, q)]; i != SLOT_NONE;
         i = c->slots[i].hash_next) {
        if (misma_clave(&c->slots[i], q)) {
            return i;
        }
    }
    return SLOT_NONE;
}

static void lru_unlink(cache_t *c, uint16_t i)
{
    struct cache_slot *s = &c->slots[i];
    if (s->lru_prev != SLOT_NONE) {
        c->slots[s->lru_prev].lru_next = s->lru_next;
    } else {
        c->lru_head = s->lru_next;
    }
    if (s->lru_next != SLOT_NONE) {
        c->slots[s->lru_next].lru_prev = s->lru_prev;
    } else {
        c->lru_tail = s->lru_prev;
    }
}

static void lru_push_front(cache_t *c, uint16_t i)
{
    struct cache_slot *s = &c->slots[i];
    s->lru_prev = SLOT_NONE;
    s->lru_next = c->lru_head;
    if (c->lru_head != SLOT_NONE) {
        c->slots[c->lru_head].lru_prev = i;
    }
    c->lru_head = i;
    if (c->lru_tail == SLOT_NONE) {
        c->lru_tail = i;
    }
}

static void hash_unlink(cache_t *c, uint16_t i)
{
    struct cache_slot *s = &c->slots[i];
    uint16_t b = (uint16_t)(hash_key(s->qname, s->qname_len, s->qtype, s->qclass) %
                            c->capacity);
    uint16_t *p = &c->buckets[b];
    while (*p != SLOT_NONE) {
        if (*p == i) {
            *p = s->hash_next;
            return;
        }
        p = &c->slots[*p].hash_next;
    }
}

/* saca el slot de todas las estructuras y lo devuelve a la free-list */
static void libera(cache_t *c, uint16_t i)
{
    hash_unlink(c, i);
    lru_unlink(c, i);
    c->slots[i].hash_next = c->free_head;
    c->free_head = i;
}

size_t cache_get(cache_t *c, const dns_query_t *q, uint32_t now, uint8_t *out,
                 size_t out_cap)
{
    if (c == NULL || c->slots == NULL || q == NULL || out == NULL) {
        return 0;
    }
    uint16_t i = busca(c, q);
    if (i == SLOT_NONE) {
        return 0;
    }
    struct cache_slot *s = &c->slots[i];
    if (s->expiry <= now) { /* jamás servir caducado (FR-005) */
        libera(c, i);
        return 0;
    }
    size_t n = s->resp_len;
    if (n > out_cap) {
        return 0;
    }
    memcpy(out, s->resp, n);
    /* eco de la pregunta con el casing del cliente actual (dns0x20): misma
     * clave ⇒ misma longitud de sección de pregunta */
    if (q->raw != NULL && q->question_end > 12 && q->question_end <= n &&
        q->question_end <= q->raw_len) {
        memcpy(out + 12, q->raw + 12, (size_t)q->question_end - 12);
    }
    dns_wire_decrement_ttls(out, n, now - s->inserted);
    dns_wire_rewrite_id(out, n, q->id);
    lru_unlink(c, i);
    lru_push_front(c, i);
    return n;
}

void cache_put(cache_t *c, const dns_query_t *q, const uint8_t *resp,
               size_t resp_len, uint32_t ttl, uint32_t now)
{
    if (c == NULL || c->slots == NULL || q == NULL || resp == NULL) {
        return;
    }
    if (ttl == 0 || resp_len < 12 || resp_len > ESPHOLE_RESP_MAX) {
        return; /* FR-016: TTL 0 y respuestas grandes no se cachean */
    }
    uint8_t rcode = dns_wire_rcode(resp, resp_len);
    if (rcode != DNS_RCODE_NOERROR && rcode != DNS_RCODE_NXDOMAIN) {
        return;
    }
    uint32_t ttl_eff = (ttl > c->ttl_cap) ? c->ttl_cap : ttl;

    uint16_t i = busca(c, q);
    if (i == SLOT_NONE) {
        if (c->free_head != SLOT_NONE) {
            i = c->free_head;
            c->free_head = c->slots[i].hash_next;
        } else {
            /* llena: expirada-primero (escaneo acotado desde la cola LRU),
             * después la propia cola (C4) */
            uint16_t victima = c->lru_tail;
            uint16_t it = c->lru_tail;
            for (int paso = 0; paso < EVICT_SCAN && it != SLOT_NONE; paso++) {
                if (c->slots[it].expiry <= now) {
                    victima = it;
                    break;
                }
                it = c->slots[it].lru_prev;
            }
            if (victima == SLOT_NONE) {
                return; /* imposible con capacity>0; defensivo */
            }
            hash_unlink(c, victima);
            lru_unlink(c, victima);
            c->evictions++;
            i = victima;
        }
        struct cache_slot *s = &c->slots[i];
        memcpy(s->qname, q->qname, (size_t)q->qname_len + 1);
        s->qname_len = q->qname_len;
        s->qtype = q->qtype;
        s->qclass = q->qclass;
        uint16_t b = bucket_de(c, q);
        s->hash_next = c->buckets[b];
        c->buckets[b] = i;
        lru_push_front(c, i);
    } else {
        lru_unlink(c, i);
        lru_push_front(c, i);
    }
    struct cache_slot *s = &c->slots[i];
    memcpy(s->resp, resp, resp_len);
    s->resp_len = (uint16_t)resp_len;
    s->inserted = now;
    s->expiry = now + ttl_eff;
}

uint32_t cache_evictions(const cache_t *c)
{
    return (c != NULL) ? c->evictions : 0;
}

void cache_clear(cache_t *c)
{
    if (c == NULL || c->slots == NULL || c->capacity == 0) {
        return;
    }
    /* vacía sin tocar la memoria del llamador: rehace free-list, buckets y LRU
     * conservando capacity/ttl_cap (evictions no se reinicia: es acumulativo). */
    c->lru_head = SLOT_NONE;
    c->lru_tail = SLOT_NONE;
    for (uint16_t i = 0; i < c->capacity; i++) {
        c->buckets[i] = SLOT_NONE;
        c->slots[i].hash_next = (uint16_t)(i + 1);
    }
    c->slots[c->capacity - 1].hash_next = SLOT_NONE;
    c->free_head = 0;
}

uint16_t cache_count(const cache_t *c)
{
    if (c == NULL || c->slots == NULL || c->capacity == 0) {
        return 0;
    }
    uint16_t n = 0;
    for (uint16_t i = c->lru_head; i != SLOT_NONE; i = c->slots[i].lru_next) {
        n++;
        if (n >= c->capacity) {
            break; /* defensivo: nunca más que capacidad */
        }
    }
    return n;
}
