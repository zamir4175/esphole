/*
 * webapi — interfaz HTTP de administración (HW, spec 003).
 * Sirve la UI estática desde la partición SPIFFS `www`, expone la API REST
 * (estado, config, caché) protegida por sesión, y el flujo de setup/login por
 * desafío-respuesta (la contraseña nunca viaja). Corre en la tarea de
 * esp_http_server, DESPUÉS de la ruta DNS: no la toca ni la degrada (AB-11).
 * La lógica pura vive en webapi_logic; aquí solo el pegamento con ESP-IDF.
 */
#ifndef ESPHOLE_WEBAPI_H
#define ESPHOLE_WEBAPI_H

#include "config_nvs.h"

/* Arranca el servidor HTTP y registra los handlers. cfg debe vivir para
 * siempre (se lee para GET /api/config y se copia para PUT). Idempotente:
 * una segunda llamada no hace nada. Devuelve false si el servidor no arrancó
 * (el resto del sistema sigue: la web es un extra, P-I). */
bool webapi_start(const esphole_config_t *cfg);

#endif /* ESPHOLE_WEBAPI_H */
