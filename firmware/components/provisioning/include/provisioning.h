/*
 * provisioning — orquestación del aprovisionamiento (HW). spec 002.
 * Levanta el AP + portal cautivo cuando hace falta, gestiona la máquina de
 * estados PROVISION/CONNECTING y retorna solo cuando hay conexión STA con IP
 * (con el AP/portal ya apagados y liberados).
 */
#ifndef ESPHOLE_PROVISIONING_H
#define ESPHOLE_PROVISIONING_H

#include "config_nvs.h"
#include "esphole_types.h"

/*
 * Ejecuta la máquina de estados de arranque. Bloquea hasta obtener IP en modo
 * STA (posiblemente tras pasar por el portal). Al retornar, cfg->wifi_* refleja
 * las credenciales en uso y el modo Wi-Fi es STA puro. Debe llamarse una vez,
 * antes de arrancar la ruta DNS de la spec 001.
 */
void provisioning_run(esphole_config_t *cfg);

/* ¿el botón BOOT (GPIO0) lleva pulsado al menos 'ms'? Para el factory reset
 * (al arranque y por polling en caliente). Muestrea con antirrebote. */
bool prov_button_held_ms(uint32_t ms);

#endif /* ESPHOLE_PROVISIONING_H */
