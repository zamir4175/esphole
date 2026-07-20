#include "dhcp_lease.h"

#include <string.h>

#define OFFER_RESERVE_S 30 /* una oferta reserva la IP este tiempo corto */

static bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, DHCP_MAC_LEN) == 0;
}

void dhcp_leases_init(dhcp_leases_t *t)
{
    if (t != NULL) {
        memset(t, 0, sizeof(*t)); /* todo LEASE_FREE */
    }
}

/* índice de la entrada (no libre) de 'mac', o -1 */
static int find_mac(dhcp_leases_t *t, const uint8_t *mac)
{
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if (t->v[i].estado != LEASE_FREE && mac_eq(t->v[i].mac, mac)) {
            return i;
        }
    }
    return -1;
}

/* índice de la entrada (no libre) de 'ip', o -1 */
static int find_ip(dhcp_leases_t *t, uint32_t ip)
{
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if (t->v[i].estado != LEASE_FREE && t->v[i].ip == ip) {
            return i;
        }
    }
    return -1;
}

/* ¿la IP está ocupada ahora? (BAD, u OFFERED/BOUND sin vencer) */
static bool ip_taken(dhcp_leases_t *t, uint32_t ip, uint32_t now)
{
    int i = find_ip(t, ip);
    if (i < 0) {
        return false;
    }
    if (t->v[i].estado == LEASE_BAD) {
        return true;
    }
    return (int32_t)(t->v[i].expira - now) > 0; /* no vencida */
}

/* IP reservable del pool: no es own/gateway, ni está ocupada */
static bool ip_usable(const dhcp_pool_t *p, dhcp_leases_t *t, uint32_t ip, uint32_t now)
{
    if (ip < p->start || ip > p->end || ip == p->own_ip || ip == p->gateway) {
        return false;
    }
    return !ip_taken(t, ip, now);
}

/* slot reutilizable: preferir FREE; si no, una entrada vencida no-BAD */
static int free_slot(dhcp_leases_t *t, uint32_t now)
{
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if (t->v[i].estado == LEASE_FREE) {
            return i;
        }
    }
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if (t->v[i].estado != LEASE_BAD && (int32_t)(t->v[i].expira - now) <= 0) {
            return i;
        }
    }
    return -1;
}

/* reserva 'ip' para 'mac' como OFFERED (reusa la entrada de la ip si existe) */
static uint32_t reservar(dhcp_leases_t *t, uint32_t ip, const uint8_t *mac, uint32_t now)
{
    int si = free_slot(t, now);
    int ei = find_ip(t, ip);
    if (ei >= 0 && t->v[ei].estado != LEASE_BAD) {
        si = ei; /* reusa la entrada vencida de esta misma ip */
    }
    if (si < 0) {
        return 0;
    }
    t->v[si].ip = ip;
    memcpy(t->v[si].mac, mac, DHCP_MAC_LEN);
    t->v[si].estado = LEASE_OFFERED;
    t->v[si].expira = now + OFFER_RESERVE_S;
    t->v[si].hostname[0] = '\0';
    return ip;
}

uint32_t dhcp_lease_offer(dhcp_leases_t *t, const dhcp_pool_t *p,
                          const uint8_t mac[DHCP_MAC_LEN], uint32_t requested,
                          uint32_t now)
{
    if (t == NULL || p == NULL || mac == NULL) {
        return 0;
    }
    /* 1. el MAC ya tiene una concesión no-BAD → renovar su IP */
    int mi = find_mac(t, mac);
    if (mi >= 0 && t->v[mi].estado != LEASE_BAD) {
        t->v[mi].estado = LEASE_OFFERED;
        t->v[mi].expira = now + OFFER_RESERVE_S;
        return t->v[mi].ip;
    }
    /* 2. honrar la IP pedida si es utilizable */
    if (requested != 0 && ip_usable(p, t, requested, now)) {
        return reservar(t, requested, mac, now);
    }
    /* 3. primera libre del pool */
    for (uint32_t ip = p->start; ip <= p->end; ip++) {
        if (ip_usable(p, t, ip, now)) {
            return reservar(t, ip, mac, now);
        }
    }
    return 0;
}

bool dhcp_lease_commit(dhcp_leases_t *t, const dhcp_pool_t *p,
                       const uint8_t mac[DHCP_MAC_LEN], uint32_t ip, uint32_t now,
                       const char *hostname)
{
    if (t == NULL || p == NULL || mac == NULL) {
        return false;
    }
    if (ip < p->start || ip > p->end || ip == p->own_ip || ip == p->gateway) {
        return false; /* no es del pool ⇒ NAK */
    }
    int ei = find_ip(t, ip);
    int si;
    if (ei >= 0) {
        if (t->v[ei].estado == LEASE_BAD) {
            return false;
        }
        bool mine = mac_eq(t->v[ei].mac, mac);
        bool vencida = (int32_t)(t->v[ei].expira - now) <= 0;
        if (!mine && !vencida) {
            return false; /* de otro cliente y activa ⇒ NAK */
        }
        si = ei;
    } else {
        si = free_slot(t, now);
        if (si < 0) {
            return false;
        }
    }
    t->v[si].ip = ip;
    memcpy(t->v[si].mac, mac, DHCP_MAC_LEN);
    t->v[si].estado = LEASE_BOUND;
    t->v[si].expira = now + p->lease_time;
    if (hostname != NULL) {
        strncpy(t->v[si].hostname, hostname, sizeof(t->v[si].hostname) - 1);
        t->v[si].hostname[sizeof(t->v[si].hostname) - 1] = '\0';
    } else {
        t->v[si].hostname[0] = '\0';
    }
    return true;
}

void dhcp_lease_release(dhcp_leases_t *t, const uint8_t mac[DHCP_MAC_LEN], uint32_t ip)
{
    if (t == NULL || mac == NULL) {
        return;
    }
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if ((t->v[i].estado == LEASE_BOUND || t->v[i].estado == LEASE_OFFERED) &&
            t->v[i].ip == ip && mac_eq(t->v[i].mac, mac)) {
            t->v[i].estado = LEASE_FREE;
            return;
        }
    }
}

void dhcp_lease_decline(dhcp_leases_t *t, uint32_t ip)
{
    if (t == NULL) {
        return;
    }
    int ei = find_ip(t, ip);
    if (ei >= 0) {
        t->v[ei].estado = LEASE_BAD;
        return;
    }
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if (t->v[i].estado == LEASE_FREE) {
            t->v[i].ip = ip;
            t->v[i].estado = LEASE_BAD;
            return;
        }
    }
}

void dhcp_lease_expire(dhcp_leases_t *t, uint32_t now)
{
    if (t == NULL) {
        return;
    }
    for (int i = 0; i < DHCP_LEASES_MAX; i++) {
        if ((t->v[i].estado == LEASE_OFFERED || t->v[i].estado == LEASE_BOUND) &&
            (int32_t)(t->v[i].expira - now) <= 0) {
            t->v[i].estado = LEASE_FREE;
        }
    }
}
