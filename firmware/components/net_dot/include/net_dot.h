/*
 * net_dot — upstream DNS cifrado por DoT (DNS over TLS, RFC 7858) (HW, spec 007).
 * Tarea dedicada con conexión esp-tls persistente al resolvedor (conectando por
 * IP y validando el certificado contra el hostname con el bundle de CAs). La
 * ruta rápida (hilo tcpip) solo ENCOLA; la tarea hace el TLS bloqueante fuera de
 * ella. Fail-closed: si ningún resolvedor cifrado responde ⇒ SERVFAIL local,
 * jamás una consulta en claro. Off por defecto (Principio X).
 * Contrato: specs/007-dot-upstream/contracts/dot-behavior.md.
 */
#ifndef ESPHOLE_NET_DOT_H
#define ESPHOLE_NET_DOT_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool enabled;         /* DoT activo (forward conmutado a la tarea DoT) */
    bool connected;       /* hay una conexión TLS viva al resolvedor */
    int active;           /* índice del upstream cifrado en uso, -1 si ninguno */
    char last_error[128]; /* último error legible (para la API/UI) */
    uint32_t served;      /* respuestas entregadas por DoT */
    uint32_t servfail;    /* consultas respondidas SERVFAIL (fail-closed) */
    uint32_t dropped;     /* consultas descartadas por cola llena (FR-007) */
} net_dot_status_t;

/*
 * Lee la config DoT (config_get_dot) + los upstreams (config_load). Si está
 * desactivada, no hace nada y devuelve true. Si está activada: guarda el forward
 * UDP actual, conmuta el forward de net_dns a la tarea DoT y arranca la tarea.
 * Si ya estaba corriendo, la reinicia con la config nueva (sirve de "reload"
 * tras un cambio desde la web). false si no pudo arrancar la tarea/cola.
 */
bool net_dot_start(void);

/* Restaura el forward UDP y para la tarea (no borra la config). */
void net_dot_stop(void);

/* Copia una instantánea del estado (para GET /api/dot). */
void net_dot_status(net_dot_status_t *out);

#endif /* ESPHOLE_NET_DOT_H */
