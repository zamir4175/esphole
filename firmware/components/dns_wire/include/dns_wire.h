/*
 * dns_wire — parseo y serialización DNS (PURO). RFC 1035 + EDNS0 (RFC 6891).
 * Contrato: specs/001-servicio-dns-core/contracts/module-interfaces.md §1.
 * Toda entrada se trata como hostil: ningún acceso fuera de [buf, buf+len).
 */
#ifndef ESPHOLE_DNS_WIRE_H
#define ESPHOLE_DNS_WIRE_H

#include "esphole_types.h"

/* Payload EDNS0 que anunciamos en nuestras respuestas (research.md R4). */
#define DNS_WIRE_OUR_EDNS_PAYLOAD 1232

typedef enum {
    DNS_WIRE_OK = 0,
    DNS_WIRE_MALFORMED,    /* violación de formato: descartar (FR-009) */
    DNS_WIRE_UNSUPPORTED,  /* bien formada pero no procesable: reenviar íntegra (FR-006) */
    DNS_WIRE_BUFFER_SMALL,
} dns_wire_err_t;

/*
 * Parsea una consulta de cliente. Valida cabecera (QR=0), QNAME (etiquetas 1..63,
 * total ≤253, sin punteros de compresión en la pregunta), y localiza el OPT en
 * additionals si existe. Normaliza qname a minúsculas. out->raw apunta a buf.
 * QDCOUNT≠1, OPCODE≠QUERY o nombre raíz → UNSUPPORTED.
 */
dns_wire_err_t dns_wire_parse_query(const uint8_t *buf, size_t len, dns_query_t *out);

/*
 * Respuesta de agujero negro: A→0.0.0.0, AAAA→::, otro tipo→ANCOUNT=0.
 * Eco de la pregunta con su casing original; OPT propio si el cliente trajo OPT.
 * Devuelve bytes escritos, 0 si buf_cap insuficiente.
 */
size_t dns_wire_build_block_response(const dns_query_t *q, uint32_t block_ttl,
                                     uint8_t *buf, size_t buf_cap);

/* Respuesta sin datos con el RCODE dado (p. ej. SERVFAIL en fail-open agotado). */
size_t dns_wire_build_rcode_response(const dns_query_t *q, uint8_t rcode,
                                     uint8_t *buf, size_t buf_cap);

/*
 * Respuesta con un único registro A apuntando a 'ip' (4 bytes IPv4), TTL dado.
 * Ecoa la pregunta (dns0x20) y copia el OPT del cliente si lo trae. Para el DNS
 * cautivo del aprovisionamiento (spec 002): responde la IP del AP a cualquier
 * consulta A. Tipos ≠ A → ANCOUNT=0. Devuelve bytes escritos, 0 si no cabe.
 */
size_t dns_wire_build_a_response(const dns_query_t *q, const uint8_t ip[4],
                                 uint32_t ttl, uint8_t *buf, size_t buf_cap);

/* Reescribe el ID de un mensaje wire (fan-out a waiters, servir de caché). */
void dns_wire_rewrite_id(uint8_t *resp, size_t len, uint16_t new_id);

/*
 * TTL mínimo de los registros de una respuesta (para caché): mínimo de la sección
 * answer; si ANCOUNT==0, TTL del SOA en authority (caché negativa). false si no
 * hay ninguno (⇒ no cachear) o el mensaje es inparseable.
 */
bool dns_wire_min_ttl(const uint8_t *resp, size_t len, uint32_t *ttl_out);

/*
 * Resta 'elapsed' a los TTL de answer y authority (servir desde caché con TTL
 * restante). No toca el pseudo-TTL del OPT (son flags). Satura en 0.
 */
dns_wire_err_t dns_wire_decrement_ttls(uint8_t *resp, size_t len, uint32_t elapsed);

/*
 * Trunca a cabecera + pregunta (+ OPT nuevo si el original lo traía) fijando TC=1
 * (CB-31). Devuelve la longitud resultante, 0 si el mensaje es inparseable.
 */
size_t dns_wire_truncate(uint8_t *resp, size_t len, size_t payload_max);

/* RCODE de un mensaje (0 si len<4). */
uint8_t dns_wire_rcode(const uint8_t *msg, size_t len);

/*
 * Construye una consulta hacia el upstream desde una clave (nombre en
 * presentación, tipo, clase): cabecera con txid y RD=1, y OPT propio si
 * with_edns. Para el primer envío y los reintentos de la tabla de pendientes.
 * Devuelve bytes escritos, 0 si no cabe o el nombre es inválido.
 */
size_t dns_wire_build_query(const char *qname, uint8_t qname_len, uint16_t qtype,
                            uint16_t qclass, uint16_t txid, bool with_edns,
                            uint8_t *buf, size_t buf_cap);

/* Payload UDP efectivo del cliente: max(512, anunciado); 512 sin OPT (RFC 6891). */
uint16_t dns_wire_edns_payload(const dns_query_t *q);

#endif /* ESPHOLE_DNS_WIRE_H */
