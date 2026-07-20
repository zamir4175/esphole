/*
 * Tipos y constantes compartidos por todos los módulos (PUROS y HW).
 * Regla dura (Principio IX): este header solo depende de la stdlib C11 —
 * ningún include de ESP-IDF ni de lwIP, jamás.
 */
#ifndef ESPHOLE_TYPES_H
#define ESPHOLE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ESPHOLE_DOMAIN_MAX 253 /* nombre normalizado máx. (RFC 1035 §2.3.4) */
#define ESPHOLE_LABEL_MAX  63  /* etiqueta máx. */
#define ESPHOLE_RESP_MAX   512 /* respuesta cacheable máx. (data-model §4) */

/* Dirección IP unificada: v4 ocupa bytes[0..3] (resto a 0), v6 los 16. */
typedef enum { ESPHOLE_AF_V4 = 4, ESPHOLE_AF_V6 = 6 } esphole_af_t;

typedef struct {
    uint8_t family; /* esphole_af_t */
    uint8_t bytes[16];
} ip_addr16_t;

typedef enum { ESPHOLE_TRANSPORT_UDP = 0, ESPHOLE_TRANSPORT_TCP = 1 } esphole_transport_t;

/* Tipos de registro (RFC 1035 §3.2.2, RFC 3596, RFC 6891) */
enum {
    DNS_TYPE_A     = 1,
    DNS_TYPE_NS    = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA   = 6,
    DNS_TYPE_PTR   = 12,
    DNS_TYPE_MX    = 15,
    DNS_TYPE_TXT   = 16,
    DNS_TYPE_AAAA  = 28,
    DNS_TYPE_OPT   = 41,
    DNS_TYPE_ANY   = 255,
};

enum { DNS_CLASS_IN = 1 };

/* RCODEs (RFC 1035 §4.1.1) */
enum {
    DNS_RCODE_NOERROR  = 0,
    DNS_RCODE_FORMERR  = 1,
    DNS_RCODE_SERVFAIL = 2,
    DNS_RCODE_NXDOMAIN = 3,
    DNS_RCODE_NOTIMP   = 4,
    DNS_RCODE_REFUSED  = 5,
};

/* Consulta DNS en vuelo (data-model §1). Vive en pila o pool, nunca en heap. */
typedef struct {
    uint16_t id;    /* ID de transacción del cliente (se preserva) */
    uint16_t flags; /* cabecera cruda; RD se preserva al reenviar */
    char     qname[ESPHOLE_DOMAIN_MAX + 1]; /* normalizado, NUL-terminado */
    uint8_t  qname_len;
    uint16_t qtype;
    uint16_t qclass;
    bool     edns_present;
    uint16_t edns_payload; /* payload UDP anunciado; 512 si no hay OPT */
    ip_addr16_t client_addr;
    uint16_t client_port;
    uint8_t  transport; /* esphole_transport_t */
    const uint8_t *raw; /* vista al datagrama original (reenvío íntegro) */
    uint16_t raw_len;
    uint16_t question_end; /* fin (exclusivo) de la sección de pregunta en raw;
                            * permite ecoar la pregunta con su casing original
                            * (clientes dns0x20 lo verifican) */
} dns_query_t;

#endif /* ESPHOLE_TYPES_H */
