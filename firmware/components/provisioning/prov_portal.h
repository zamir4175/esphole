/*
 * prov_portal — interfaz interna entre el portal (prov_portal.c) y la
 * orquestación (provisioning.c). No es API pública del componente.
 */
#ifndef ESPHOLE_PROV_PORTAL_H
#define ESPHOLE_PROV_PORTAL_H

#include <stdbool.h>

/* Levanta AP (APSTA) + DHCP-114 + DNS cautivo + http server + escaneo. */
void portal_start(void);

/* Bloquea hasta que un POST /save válido persista credenciales en NVS. */
bool portal_wait_saved(void);

/* Detiene http server + DNS cautivo y baja el AP, liberando recursos (R7). */
void portal_stop(void);

#endif /* ESPHOLE_PROV_PORTAL_H */
