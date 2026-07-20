/*
 * provision_logic — lógica pura del aprovisionamiento (PURO).
 * Contrato: specs/002-aprovisionamiento-inicial/contracts/provision-logic.md.
 * C11, sin dependencias de ESP-IDF. Toda entrada del formulario es hostil.
 */
#ifndef ESPHOLE_PROVISION_LOGIC_H
#define ESPHOLE_PROVISION_LOGIC_H

#include "esphole_types.h"

#define PROV_SSID_MAX 32 /* IEEE 802.11 */
#define PROV_PASS_MAX 64 /* WPA2: 8..63 + NUL */

typedef struct {
    char ssid[PROV_SSID_MAX + 1];
    char pass[PROV_PASS_MAX + 1];
} prov_creds_t;

typedef enum {
    PROV_FORM_OK = 0,
    PROV_FORM_MALFORMED, /* urlencoding inválido o campo ssid ausente */
    PROV_FORM_TOO_LONG,  /* ssid o pass exceden su tope */
} prov_form_err_t;

/*
 * Parsea un cuerpo x-www-form-urlencoded "ssid=..&pass=.." (orden indiferente,
 * otros campos ignorados). Decodifica %XX y '+'→espacio. Rechaza %XX inválido
 * y campos sobre-largos. Preserva no-ASCII ya decodificado.
 */
prov_form_err_t provision_form_parse(const char *body, size_t len,
                                     prov_creds_t *out);

/*
 * Validez para intentar conectar: SSID 1..32 bytes sin bytes de control (<0x20);
 * pass vacío (red abierta) o 8..63 bytes (WPA2).
 */
bool provision_creds_valid(const prov_creds_t *c);

/*
 * Nombre del AP: "ESPHole-XXXX" (dos últimos bytes del MAC en hex mayúsculas).
 * El SSID no es secreto (se emite en las balizas); derivarlo del MAC está bien.
 * out_ssid ≥ 14 bytes.
 */
void provision_ap_ssid(const uint8_t mac[6], char *out_ssid);

/*
 * Codifica 8 bytes ALEATORIOS en una clave WPA2 de 10 chars imprimibles
 * [33..126]. Los bytes DEBEN venir de un RNG por hardware (esp_fill_random):
 * la clave NO puede derivarse de valores públicos como el MAC, que se observa
 * por el aire en el BSSID (Principio V — la clave debe ser un secreto real).
 * out_pass ≥ 11 bytes.
 */
void provision_ap_pass(const uint8_t rand_bytes[8], char *out_pass);

typedef enum { PROV_MODE_PROVISION = 0, PROV_MODE_CONNECTING } prov_mode_t;

/*
 * Decide el modo de arranque: boot_held → PROVISION (el llamador ya borró las
 * creds); !has_creds → PROVISION; resto → CONNECTING. 'provisioned' no cambia
 * la decisión (política centralizada aquí para auditarla en un solo sitio puro).
 */
prov_mode_t provision_decide_boot(bool has_creds, bool provisioned,
                                  bool boot_held);

#endif /* ESPHOLE_PROVISION_LOGIC_H */
