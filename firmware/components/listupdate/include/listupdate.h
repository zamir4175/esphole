/*
 * listupdate — actualización de la lista de bloqueo desde una URL (HW, spec 004).
 * Descarga en streaming (HTTPS con bundle de CAs), parsea con `hostlist`,
 * reconstruye la lista EN CALIENTE reutilizando su buffer PSRAM (sin reboot) y
 * la persiste a la partición. Corre en una tarea dedicada, aislada de la ruta
 * DNS; solo una actualización a la vez. Ante fallo, restaura la lista previa.
 * Contrato: specs/004-listas-desde-url/contracts/list-update-api.md.
 */
#ifndef ESPHOLE_LISTUPDATE_H
#define ESPHOLE_LISTUPDATE_H

#include <stdbool.h>
#include <stdint.h>

#include "blocklist.h"

typedef enum {
    LU_IDLE = 0,   /* nunca corrió */
    LU_DOWNLOADING,
    LU_BUILDING,   /* parseo + add + finalize */
    LU_WRITING,    /* serialización a la partición */
    LU_OK,         /* última actualización con éxito */
    LU_ERROR,      /* última actualización falló (ver 'error') */
} lu_estado_t;

typedef struct {
    lu_estado_t estado;
    uint32_t count;       /* dominios de la lista activa tras la última corrida */
    uint32_t descargados; /* bytes descargados (progreso) */
    char error[64];       /* motivo si estado==LU_ERROR */
    uint32_t cuando_s;    /* uptime (s) de la última finalización */
    bool en_curso;        /* true mientras una actualización está corriendo */
} listupdate_status_t;

/* Registra el handle de la lista viva (la que app_main construyó en PSRAM).
 * Debe vivir para siempre. Llamar una vez al arranque. */
void listupdate_start(blocklist_t *bl);

/*
 * Dispara una actualización desde 'url' (http/https). Valida el esquema, marca
 * "en curso" y crea la tarea. Devuelve false si la URL es inválida o ya hay una
 * actualización en curso (una a la vez, FR-010).
 */
bool listupdate_trigger(const char *url);

/* Copia el estado actual (para GET /api/blocklist / polling de la UI). */
void listupdate_status(listupdate_status_t *out);

#endif /* ESPHOLE_LISTUPDATE_H */
