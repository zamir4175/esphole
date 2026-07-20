/*
 * otaupdate — actualización de firmware por aire (HW, spec 005).
 * Descarga la imagen desde una URL (HTTPS con bundle de CAs) a la ranura de app
 * inactiva con esp_https_ota, y gestiona la vuelta atrás automática: la imagen
 * nueva arranca "a prueba" (PENDING_VERIFY) y se confirma solo si el arranque
 * completa sano; si no, el bootloader revierte. Contrato:
 * specs/005-ota-firmware/contracts/ota-api.md.
 */
#ifndef ESPHOLE_OTAUPDATE_H
#define ESPHOLE_OTAUPDATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --- ciclo de arranque (O02) --- */

/*
 * A llamar TEMPRANO en el arranque (tras nvs_flash_init). Si la ranura en
 * ejecución está PENDING_VERIFY (primer arranque tras una OTA), arma un timer de
 * gracia: si el arranque no se confirma a tiempo, reinicia ⇒ el bootloader
 * revierte a la versión anterior. En un arranque normal no hace nada.
 */
void otaupdate_boot_check(void);

/*
 * A llamar al FINAL del arranque, cuando el sistema está sano (Wi-Fi con IP y
 * servicios en marcha). Confirma la ranura en ejecución como válida
 * (cancela cualquier rollback pendiente) y desarma el timer de gracia.
 */
void otaupdate_confirm_healthy(void);

/* --- descarga y estado (O03) --- */

typedef enum {
    OTA_IDLE = 0,
    OTA_DOWNLOADING, /* escribiendo a la ranura inactiva */
    OTA_DONE,        /* imagen validada; reinicio inminente */
    OTA_ERROR,
} ota_estado_t;

typedef struct {
    ota_estado_t estado;
    uint32_t leido;    /* bytes escritos hasta ahora */
    uint32_t total;    /* tamaño de la imagen (0 si aún desconocido) */
    char error[64];    /* motivo si estado==OTA_ERROR */
    uint32_t cuando_s; /* uptime (s) de la última finalización */
    bool en_curso;
} otaupdate_status_t;

/* Versión en ejecución (esp_app_get_description) y ranura activa (ota_0/ota_1). */
void otaupdate_running_version(char *out, size_t cap);
void otaupdate_running_slot(char *out, size_t cap);

/*
 * Dispara una OTA desde 'url' (http/https). Valida el esquema, marca "en curso"
 * y crea la tarea dedicada. Devuelve false si la URL es inválida o ya hay una
 * OTA en curso (una a la vez, FR-010). En éxito, la tarea reinicia el equipo.
 */
bool otaupdate_trigger(const char *url);

/* Copia el estado actual (para GET /api/firmware / polling de la UI). */
void otaupdate_status(otaupdate_status_t *out);

#endif /* ESPHOLE_OTAUPDATE_H */
