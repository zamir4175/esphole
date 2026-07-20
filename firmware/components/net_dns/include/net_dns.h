/*
 * net_dns — listener UDP del puerto 53 sobre el API raw de lwIP (R1).
 * El callback corre en el hilo tcpip y ejecuta el camino rápido completo
 * inline (policy → ratelimit → parse → blocklist → cache) sin bloquear
 * JAMÁS: un miss se delega a la tarea upstream vía callback registrado.
 */
#ifndef ESPHOLE_NET_DNS_H
#define ESPHOLE_NET_DNS_H

#include "blocklist.h"
#include "cache.h"
#include "clients.h"
#include "config_nvs.h"
#include "esphole_types.h"
#include "policy.h"

#define NET_DNS_MAX_QUERY 576 /* consultas UDP entrantes mayores se descartan */

/* Delegado de reenvío (tarea upstream). Si no hay ninguno registrado, un miss
 * responde SERVFAIL inline (equivale a "todos los upstreams caídos", P-I). */
typedef void (*net_dns_forward_fn)(const dns_query_t *q);

/* Arranca el listener. policy/blocklist/cache/config deben vivir para siempre. */
bool net_dns_start(const esphole_config_t *cfg, const policy_t *pol,
                   blocklist_t *bl, cache_t *cache);

/* Listener TCP (RFC 7766): misma ruta de resolución, framing de 2 bytes,
 * conexiones concurrentes acotadas (FR-014). Llamar tras net_dns_start. */
bool net_dns_tcp_start(const esphole_config_t *cfg, const policy_t *pol);

/* Veredicto del camino rápido compartido UDP/TCP. */
typedef enum {
    NET_DNS_RESP = 0, /* respuesta inmediata escrita en out */
    NET_DNS_FORWARD,  /* miss: q_out relleno para el camino asíncrono */
    NET_DNS_DROP,     /* descartar en silencio */
} net_dns_verdict_t;

/* Ejecuta el camino rápido DESDE OTRA TAREA saltando al hilo tcpip y
 * esperando el resultado (para el listener TCP). q_out->raw apunta al
 * buffer 'query' del llamador. */
net_dns_verdict_t net_dns_resolve_for_tcp(const uint8_t *query, size_t qlen,
                                          const ip_addr16_t *src,
                                          uint16_t src_port, uint8_t *out,
                                          size_t out_cap, size_t *out_len,
                                          dns_query_t *q_out);

void net_dns_set_forward(net_dns_forward_fn fn);

/* Delegado de reenvío actual (para guardarlo/restaurarlo al conmutar a DoT y
 * de vuelta, spec 007). NULL si no hay ninguno registrado. */
net_dns_forward_fn net_dns_get_forward(void);

/* Registro de clientes (spec 008): instantánea consistente de la tabla por IP,
 * tomada en el hilo tcpip (sin carreras con el conteo del camino rápido). Copia
 * hasta 'cap' entradas en uso; devuelve cuántas. */
size_t net_dns_clients_snapshot(client_ent_t *out, size_t cap);
/* Reinicia la tabla de clientes (DELETE /api/clients), en el hilo tcpip. */
void net_dns_clients_reset(void);

/* Cachea una respuesta reenviada por una tarea que NO corre en el hilo tcpip
 * (p. ej. la tarea DoT, spec 007): salta al hilo tcpip y espera, evitando
 * carreras con cache_get del camino rápido. Filtra RCODE/TTL como cache_put.
 * 'q' debe traer qname/qname_len/qtype/qclass; no toma posesión de los buffers. */
void net_dns_cache_put_task(const dns_query_t *q, const uint8_t *resp, size_t len);

/* API de administración (spec 003). El vaciado corre en el hilo tcpip (sin
 * carreras con la ruta DNS); la cuenta es una lectura benigna de monitoreo. */
void net_dns_cache_flush(void);
uint16_t net_dns_cache_count(void);

/* spec 004: suspende el bloqueo poniendo la lista en BL_EMPTY desde el hilo
 * tcpip (fail-open: todo se reenvía) mientras se reconstruye la lista sin
 * carreras con el camino rápido. El retorno a ACTIVE lo hace blocklist_finalize. */
void net_dns_blocklist_suspend(void);

/* Responde a un cliente UDP desde OTRA tarea (toma el lock del core de lwIP,
 * CONFIG_LWIP_TCPIP_CORE_LOCKING, R1). */
bool net_dns_send_response(const ip_addr16_t *dst, uint16_t port,
                           const uint8_t *resp, size_t len);

/* Igual pero para código que YA corre en el hilo tcpip (callbacks raw,
 * tcpip_callback): el lock del core NO es reentrante. */
void net_dns_send_from_tcpip(const ip_addr16_t *dst, uint16_t port,
                             const uint8_t *resp, size_t len);

#endif /* ESPHOLE_NET_DNS_H */
