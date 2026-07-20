/*
 * config_nvs — configuración persistente con defectos compilados (P-VIII).
 * data-model.md §9. Regla dura: el arranque NUNCA depende de la configuración —
 * clave ausente o corrupta ⇒ defecto compilado, sin error fatal.
 */
#ifndef ESPHOLE_CONFIG_NVS_H
#define ESPHOLE_CONFIG_NVS_H

#include <stddef.h>

#include "esphole_types.h"

#define CONFIG_UPSTREAMS_MAX 4
#define ESPHOLE_CFG_VERSION 1
#define BL_URL_MAX 200 /* longitud máx. de la URL de la lista (spec 004) */
#define DOT_SNI_MAX 64 /* hostname/SNI máx. por upstream cifrado (spec 007) */

typedef struct {
    ip_addr16_t upstream_addr[CONFIG_UPSTREAMS_MAX];
    uint16_t upstream_port[CONFIG_UPSTREAMS_MAX];
    uint8_t upstream_count;
    uint16_t udp_payload; /* EDNS0 nuestro (R4) */
    uint16_t block_ttl;   /* TTL de respuestas de agujero negro */
    uint16_t cache_cap;   /* entradas de caché */
    uint32_t ttl_cap;     /* tope de TTL cacheado (s) */
    uint16_t rl_ip_rate, rl_ip_burst;
    uint16_t rl_glob_rate, rl_glob_burst;
    /* Aprovisionamiento (spec 002): credenciales Wi-Fi y marca de validez. */
    char wifi_ssid[33]; /* vacío ⇒ sin aprovisionar ⇒ modo AP */
    char wifi_pass[65];
    uint8_t provisioned; /* 0 = las credenciales aún no lograron conectividad */
} esphole_config_t;

/* Defectos compilados (C3: Cloudflare primario, Quad9 secundario; R4: 1232). */
void config_defaults(esphole_config_t *cfg);

/* defaults + overrides de NVS. Nunca falla: lo ilegible queda en defecto. */
void config_load(esphole_config_t *cfg);

/* Guarda todo el struct en NVS con commit (atómico por clave). */
bool config_save(const esphole_config_t *cfg);

/*
 * Aprovisionamiento (spec 002). Guardado atómico: las credenciales primero,
 * la marca de validez después, de modo que un corte a mitad caiga en "sin
 * aprovisionar" en vez de dejar el dispositivo inservible (FR-006/C1).
 */
bool config_save_wifi(const char *ssid, const char *pass); /* fija provisioned=0 */
bool config_mark_provisioned(void); /* sube provisioned=1 tras validar conexión */
bool config_clear_wifi(void);       /* factory reset: borra ssid/pass/provisioned Y admin */

/*
 * Credencial de administración (spec 003). Se guarda el hash SHA-256(salt‖P) y
 * el salt; la contraseña en claro nunca se persiste ni viaja (FR-002/FR-009).
 * Guardado atómico: hash y salt en la misma transacción, commit al final.
 */
bool config_set_admin(const uint8_t h[32], const uint8_t salt[16]);
/* Copia hash+salt en las salidas; false si aún no hay admin fijada (modo SETUP). */
bool config_get_admin(uint8_t h[32], uint8_t salt[16]);
/* Borra la credencial (vuelve a modo SETUP). Lo invoca también el factory reset. */
bool config_clear_admin(void);

/*
 * URL de la lista de bloqueo (spec 004). Ausente en NVS ⇒ default compilado
 * (CONFIG_ESPHOLE_BLOCKLIST_URL). 'out' se NUL-termina; 'cap' incluye el NUL.
 */
void config_get_blocklist_url(char *out, size_t cap);
/* Persiste la URL (clave NVS 'bl_url'). false si es NULL o > BL_URL_MAX. */
bool config_set_blocklist_url(const char *url);

/*
 * Servidor DHCP opcional (spec 006). Ausentes en NVS ⇒ enabled=false y
 * pool_start/pool_end/lease_time=0 (el llamador auto-deriva de la STA). Los
 * punteros que no interesen pueden ser NULL. IPs en orden de host.
 */
void config_get_dhcp(bool *enabled, uint32_t *pool_start, uint32_t *pool_end,
                     uint32_t *lease_time);
bool config_set_dhcp(bool enabled, uint32_t pool_start, uint32_t pool_end,
                     uint32_t lease_time);

/*
 * Upstream DNS cifrado (DoT, spec 007). Ausente en NVS ⇒ enabled=false y SNI por
 * defecto que casan con los IPs de upstream por defecto (Cloudflare/Quad9):
 * [0]=one.one.one.one, [1]=dns.quad9.net, [2]=one.one.one.one, [3]=dns.quad9.net.
 * 'sni' es una matriz [CONFIG_UPSTREAMS_MAX][DOT_SNI_MAX]; cada fila se NUL-termina.
 * Los punteros que no interesen pueden ser NULL.
 */
void config_get_dot(bool *enabled, char sni[][DOT_SNI_MAX]);
/* Persiste enabled + los SNI (clave 'dot_en' + blob 'dot_sni'). false en error de
 * NVS. Cada fila de 'sni' debe estar NUL-terminada y caber en DOT_SNI_MAX. */
bool config_set_dot(bool enabled, const char sni[][DOT_SNI_MAX]);

#endif /* ESPHOLE_CONFIG_NVS_H */
