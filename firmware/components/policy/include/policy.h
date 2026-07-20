/*
 * policy — decisiones de origen local y fail-open centralizado (PURO).
 * Contrato: specs/001-servicio-dns-core/contracts/module-interfaces.md §6.
 */
#ifndef ESPHOLE_POLICY_H
#define ESPHOLE_POLICY_H

#include "dns_wire.h"
#include "esphole_types.h"

typedef struct {
    ip_addr16_t base;
    uint8_t prefix_len; /* bits: ≤32 en v4, ≤128 en v6 */
} subnet_t;

typedef struct {
    subnet_t subnets[4];
    uint8_t count;
} policy_t;

/*
 * ¿El origen está en alguna subred local configurada? false ⇒ ignorar sin
 * responder (no-resolvedor-abierto, CB-41/R6). Sin subredes configuradas
 * nada es local: la capa de red SIEMPRE configura al menos la subred de la
 * interfaz activa.
 */
bool policy_is_local(const policy_t *p, const ip_addr16_t *src);

/*
 * Tabla única de decisión ante error en el camino rápido: MALFORMED se
 * descarta; todo lo demás degrada a reenvío (fail-open, P-I). Centralizada
 * aquí para poder testearla y auditarla en un solo sitio.
 */
typedef enum { POLICY_FORWARD = 0, POLICY_DROP } policy_action_t;

policy_action_t policy_on_datapath_error(dns_wire_err_t err);

#endif /* ESPHOLE_POLICY_H */
