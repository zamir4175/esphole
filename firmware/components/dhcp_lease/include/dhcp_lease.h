/*
 * dhcp_lease — tabla de concesiones DHCP y asignación de IPs (PURO). spec 006.
 * Contrato: specs/006-servidor-dhcp/contracts/dhcp-lease.md.
 * Reloj inyectado ('now' en s monotónicos), memoria estática, cero asignación.
 * IPs en uint32 en orden de HOST. Sin dependencias de ESP-IDF.
 */
#ifndef ESPHOLE_DHCP_LEASE_H
#define ESPHOLE_DHCP_LEASE_H

#include <stdbool.h>
#include <stdint.h>

#define DHCP_LEASES_MAX 32
#define DHCP_MAC_LEN 6

typedef struct {
    uint32_t start, end; /* rango del pool (inclusive), orden de host */
    uint32_t mask, gateway, dns, own_ip;
    uint32_t lease_time; /* segundos */
} dhcp_pool_t;

typedef enum { LEASE_FREE = 0, LEASE_OFFERED, LEASE_BOUND, LEASE_BAD } lease_state_t;

typedef struct {
    uint32_t ip;
    uint8_t mac[DHCP_MAC_LEN];
    uint32_t expira; /* s monotónicos (OFFERED: corta; BOUND: lease_time) */
    lease_state_t estado;
    char hostname[32];
} dhcp_lease_t;

typedef struct {
    dhcp_lease_t v[DHCP_LEASES_MAX];
} dhcp_leases_t;

void dhcp_leases_init(dhcp_leases_t *t);

/* Elige una IP para 'mac': su lease actual si la tiene; si pide 'requested' y
 * está libre y en el pool, esa (honrar); si no, la primera libre del pool.
 * Marca OFFERED. Devuelve la IP (orden de host), o 0 si no hay disponible. */
uint32_t dhcp_lease_offer(dhcp_leases_t *t, const dhcp_pool_t *p,
                          const uint8_t mac[DHCP_MAC_LEN], uint32_t requested,
                          uint32_t now);

/* REQUEST: confirma 'ip' para 'mac' si es del pool y libre-o-suya y no BAD ⇒
 * BOUND (expira=now+lease_time), true (ACK); en caso contrario false (NAK). */
bool dhcp_lease_commit(dhcp_leases_t *t, const dhcp_pool_t *p,
                       const uint8_t mac[DHCP_MAC_LEN], uint32_t ip, uint32_t now,
                       const char *hostname);

/* RELEASE: libera la concesión de 'mac'/'ip' (pasa a FREE). */
void dhcp_lease_release(dhcp_leases_t *t, const uint8_t mac[DHCP_MAC_LEN], uint32_t ip);

/* DECLINE: marca 'ip' como BAD (no se vuelve a ofrecer). */
void dhcp_lease_decline(dhcp_leases_t *t, uint32_t ip);

/* Libera (FREE) las concesiones OFFERED/BOUND vencidas (expira<=now). BAD no caduca. */
void dhcp_lease_expire(dhcp_leases_t *t, uint32_t now);

#endif /* ESPHOLE_DHCP_LEASE_H */
