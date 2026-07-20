/*
 * cache — caché DNS de capacidad fija: expira-primero + LRU, tope de TTL (PURO).
 * Contrato: specs/001-servicio-dns-core/contracts/module-interfaces.md §4.
 * Reloj inyectado ('now' en segundos monotónicos). Memoria del llamador,
 * dimensionada con cache_mem_size(); cero asignación en caliente (P-II).
 */
#ifndef ESPHOLE_CACHE_H
#define ESPHOLE_CACHE_H

#include "esphole_types.h"

typedef struct cache cache_t;

/* Campos privados: no tocar fuera del módulo. Definidos aquí para poder
 * declarar cache_t en pila/estático. */
struct cache {
    struct cache_slot *slots;
    uint16_t *buckets;
    uint16_t capacity;
    uint32_t ttl_cap;
    uint16_t lru_head, lru_tail, free_head;
    uint32_t evictions;
};

/* Bytes de 'mem' necesarios para 'capacity' entradas. */
size_t cache_mem_size(uint16_t capacity);

void cache_init(cache_t *c, void *mem, uint16_t capacity, uint32_t ttl_cap);

/*
 * Acierto ⇒ escribe en out la respuesta lista para el cliente q: pregunta
 * ecoada con el casing de q (dns0x20), ID de q y TTLs decrementados por el
 * tiempo transcurrido. Devuelve bytes, 0 si miss o expirada (jamás sirve
 * caducado, FR-005). Refresca la posición LRU.
 */
size_t cache_get(cache_t *c, const dns_query_t *q, uint32_t now,
                 uint8_t *out, size_t out_cap);

/*
 * Inserta una respuesta reenviada. Ignora (sin error) si ttl==0,
 * resp_len>ESPHOLE_RESP_MAX o RCODE ∉ {NOERROR, NXDOMAIN}. TTL efectivo
 * = min(ttl, ttl_cap). Clave existente se reemplaza. Con caché llena
 * desaloja una expirada si la hay cerca de la cola LRU; si no, la cola.
 */
void cache_put(cache_t *c, const dns_query_t *q, const uint8_t *resp,
               size_t resp_len, uint32_t ttl, uint32_t now);

uint32_t cache_evictions(const cache_t *c);

/* Vacía la caché (spec 003, DELETE /api/cache): tras esto no sirve nada hasta
 * repoblar. Conserva capacidad/ttl_cap; evictions es acumulativo, no se reinicia. */
void cache_clear(cache_t *c);

/* Entradas ocupadas actualmente (para GET /api/cache). O(n) sobre la LRU. */
uint16_t cache_count(const cache_t *c);

#endif /* ESPHOLE_CACHE_H */
