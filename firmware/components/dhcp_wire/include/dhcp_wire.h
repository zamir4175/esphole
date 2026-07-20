/*
 * dhcp_wire — formato de paquete DHCP (BOOTP + opciones) (PURO). spec 006.
 * Contrato: specs/006-servidor-dhcp/contracts/dhcp-wire.md.
 * C11, sin dependencias de ESP-IDF. Todo paquete de entrada es hostil.
 * IPs en uint32 en orden de HOST (el módulo hace la conversión a/desde red).
 */
#ifndef ESPHOLE_DHCP_WIRE_H
#define ESPHOLE_DHCP_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DHCP_MAC_LEN 6
#define DHCP_MIN_LEN 240 /* BOOTP fijo (236) + cookie mágica (4) */

typedef enum {
    DHCP_DISCOVER = 1,
    DHCP_OFFER = 2,
    DHCP_REQUEST = 3,
    DHCP_DECLINE = 4,
    DHCP_ACK = 5,
    DHCP_NAK = 6,
    DHCP_RELEASE = 7,
    DHCP_INFORM = 8,
} dhcp_msgtype_t;

/* Datos extraídos de un DISCOVER/REQUEST/RELEASE/DECLINE entrante. */
typedef struct {
    uint8_t msgtype;            /* opción 53; 0 si ausente */
    uint32_t xid;
    uint16_t flags;            /* bit 15 = broadcast */
    uint32_t ciaddr;           /* IP actual del cliente (renovación) */
    uint8_t mac[DHCP_MAC_LEN]; /* chaddr (hlen==6) */
    uint32_t requested_ip;     /* opción 50; 0 si ausente */
    uint32_t server_id;        /* opción 54; 0 si ausente */
    char hostname[32];         /* opción 12; "" si ausente */
} dhcp_request_t;

/* Parsea un paquete DHCP entrante. false si no es DHCP válido (magic, tamaño,
 * op, hlen). Solo lee dentro de [pkt, pkt+len). */
bool dhcp_parse(const uint8_t *pkt, size_t len, dhcp_request_t *out);

/* Descripción de la respuesta a construir. */
typedef struct {
    uint8_t msgtype;              /* OFFER / ACK / NAK */
    uint32_t xid;
    uint16_t flags;
    uint32_t yiaddr;             /* IP ofrecida (0 en NAK) */
    const uint8_t *mac;          /* chaddr a ecoar (6 bytes) */
    uint32_t server_id;          /* IP de ESPHole */
    uint32_t mask, gateway, dns; /* opciones 1/3/6 (dns = ESPHole) */
    uint32_t lease_time;         /* opción 51 (s) */
} dhcp_reply_t;

/* Construye el paquete de respuesta en out. Devuelve bytes escritos, 0 si no
 * cabe en cap. */
size_t dhcp_build(const dhcp_reply_t *r, uint8_t *out, size_t cap);

#endif /* ESPHOLE_DHCP_WIRE_H */
