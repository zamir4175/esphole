/*
 * clients — registro por cliente (IP) de actividad DNS (PURO). Tabla fija con
 * desalojo LRU y reloj inyectado (segundos monotónicos). Calca el patrón de
 * `ratelimit`. Contrato: specs/008-clientes/contracts/clients-table.md (CL-01..08).
 * Sin ESP-IDF. Efímero (RAM): el llamador la reinicia en cada arranque.
 */
#ifndef ESPHOLE_CLIENTS_H
#define ESPHOLE_CLIENTS_H

#include "esphole_types.h"

#define CLIENTS_TABLE 64 /* IPs simultáneas; desalojo LRU (como ratelimit) */

typedef struct {
    ip_addr16_t ip;
    uint32_t    total;   /* consultas válidas de este cliente */
    uint32_t    blocked; /* de esas, cuántas bloqueadas */
    uint32_t    visto_s; /* última consulta (segundos, reloj inyectado); clave LRU */
    bool        en_uso;
} client_ent_t;

typedef struct {
    client_ent_t e[CLIENTS_TABLE];
} clients_t;

/* Pone la tabla a cero (ninguna entrada en uso). */
void clients_init(clients_t *c);

/*
 * Registra una consulta del cliente 'ip': si ya está, total++ (y blocked++ si
 * 'blocked') y fija visto_s=now_s; si no está, crea la entrada. Si la tabla está
 * llena, desaloja la de visto_s MÍNIMO (vista hace más tiempo, LRU).
 */
void clients_record(clients_t *c, const ip_addr16_t *ip, bool blocked, uint32_t now_s);

/* Copia las entradas EN USO a out[0..cap); devuelve cuántas copió (≤cap). */
size_t clients_snapshot(const clients_t *c, client_ent_t *out, size_t cap);

/* Vacía la tabla (equivale a clients_init). */
void clients_reset(clients_t *c);

#endif /* ESPHOLE_CLIENTS_H */
