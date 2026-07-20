/*
 * pending — tabla de consultas pendientes: dedupe + fan-out + timeout (PURO).
 * Lógica del componente upstream, testeable en host: reloj y aleatoriedad
 * inyectados (R5, Principio IX). Memoria del llamador (pending_mem_size).
 * La validación de IP/puerto de origen de la respuesta la hace el llamador HW;
 * aquí se valida txid + que la pregunta de la respuesta case con la clave.
 */
#ifndef ESPHOLE_PENDING_H
#define ESPHOLE_PENDING_H

#include "esphole_types.h"

#define PENDING_ENTRIES 64
#define PENDING_WAITERS 8

typedef struct {
    ip_addr16_t addr;
    uint16_t port;
    uint16_t id_original;
    uint8_t transport;
    bool edns_present;
    uint16_t edns_payload;
} pending_waiter_t;

typedef struct {
    /* clave e instante de envío: para cache_put y métrica de latencia */
    char qname[ESPHOLE_DOMAIN_MAX + 1];
    uint8_t qname_len;
    uint16_t qtype, qclass;
    uint32_t enviado_en; /* ms */
    uint8_t count;
    pending_waiter_t w[PENDING_WAITERS];
} pending_waiters_t;

typedef enum {
    PENDING_ACT_RETRY = 0, /* reenviar la clave con new_txid al siguiente upstream */
    PENDING_ACT_FAIL,      /* agotado: SERVFAIL a los waiters y entrada liberada */
} pending_action_kind_t;

typedef struct {
    pending_action_kind_t kind;
    uint16_t new_txid;   /* RETRY: txid ya actualizado en la entrada */
    uint8_t upstream_idx; /* RETRY: índice sugerido (anterior + 1) */
    char qname[ESPHOLE_DOMAIN_MAX + 1];
    uint8_t qname_len;
    uint16_t qtype, qclass;
    pending_waiters_t waiters; /* FAIL: a quién responder SERVFAIL */
} pending_action_t;

typedef struct pending_table pending_table_t;

/* Definición visible solo para dimensionar; campos privados. */
struct pending_table {
    struct pending_entry *entries; /* PENDING_ENTRIES, en mem */
    uint16_t (*rand16)(void);
    pending_waiters_t entrega; /* buffer de la última pending_match */
    uint32_t overflow;         /* desalojos por tabla llena (observable) */
};

size_t pending_mem_size(void);

void pending_init(pending_table_t *t, void *mem, uint16_t (*rand16)(void));

typedef enum {
    PENDING_SEND = 0,  /* primera de esta clave: enviar con *txid_out */
    PENDING_GROUPED,   /* ya en vuelo: waiter añadido, no enviar */
    PENDING_SEND_SOLO, /* waiters lleno o tabla llena (desalojada la más
                          antigua): enviar sin agrupar con *txid_out */
} pending_verdict_t;

pending_verdict_t pending_register(pending_table_t *t, const dns_query_t *q,
                                   uint8_t upstream_idx, uint32_t now_ms,
                                   uint16_t *txid_out);

/*
 * Casa una respuesta upstream por txid y verifica que su pregunta coincide
 * con la clave (anti-poisoning). Devuelve los waiters (válidos hasta la
 * siguiente llamada) y libera la entrada; NULL si no casa (CB-44).
 */
const pending_waiters_t *pending_match(pending_table_t *t, uint16_t txid,
                                       const uint8_t *resp, size_t len);

/*
 * ¿A qué upstream se envió la entrada con este txid? Para que el llamador HW
 * valide IP/puerto de origen ANTES de pending_match (R5). false si no existe.
 */
bool pending_upstream_of(const pending_table_t *t, uint16_t txid,
                         uint8_t *idx_out);

/*
 * Procesa entradas vencidas a now_ms: primer vencimiento ⇒ acción RETRY
 * (la entrada sigue viva con txid nuevo); segundo ⇒ FAIL con sus waiters y
 * entrada liberada. Devuelve cuántas acciones escribió (≤ actions_cap).
 */
size_t pending_expire(pending_table_t *t, uint32_t now_ms, uint32_t timeout_ms,
                      pending_action_t *actions, size_t actions_cap);

#endif /* ESPHOLE_PENDING_H */
