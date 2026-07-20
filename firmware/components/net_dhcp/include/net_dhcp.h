/*
 * net_dhcp — servidor DHCP opcional en la LAN (HW, spec 006).
 * Socket UDP :67 en su propia tarea, aislado de la ruta DNS. Reparte IPs del
 * pool entregándose a sí mismo como DNS; auto-deriva gateway/máscara/DNS de la
 * conexión STA. Concesiones efímeras (RAM). Off por defecto (Principio X).
 * Contrato: specs/006-servidor-dhcp/contracts/dhcp-behavior.md.
 */
#ifndef ESPHOLE_NET_DHCP_H
#define ESPHOLE_NET_DHCP_H

#include <stdbool.h>
#include <stdint.h>

#include "dhcp_lease.h"

/*
 * Lee la config DHCP (config_get_dhcp). Si está activada, auto-deriva lo no
 * fijado de la STA y arranca el servidor en su tarea; si no, no hace nada. Si
 * ya había un servidor corriendo, lo reinicia con la config nueva (sirve de
 * "reload" tras un cambio desde la web). Devuelve false si no pudo arrancar. */
bool net_dhcp_start(void);

/* Para el servidor si está corriendo (no borra la config). */
void net_dhcp_stop(void);

typedef struct {
    uint32_t ip;
    uint8_t mac[DHCP_MAC_LEN];
    uint32_t expira_s;
    char hostname[32];
    uint8_t estado; /* lease_state_t */
} net_dhcp_lease_t;

typedef struct {
    bool enabled;
    uint32_t pool_start, pool_end, mask, gateway, dns, lease_time;
    uint32_t count;
    net_dhcp_lease_t leases[DHCP_LEASES_MAX];
} net_dhcp_status_t;

/* Copia una instantánea del estado (para GET /api/dhcp). */
void net_dhcp_status(net_dhcp_status_t *out);

#endif /* ESPHOLE_NET_DHCP_H */
