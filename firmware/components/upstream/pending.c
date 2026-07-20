#include "pending.h"

#include <string.h>

struct pending_entry {
    bool en_uso;
    char qname[ESPHOLE_DOMAIN_MAX + 1];
    uint8_t qname_len;
    uint16_t qtype, qclass;
    uint16_t txid;       /* aleatorio, propio hacia el upstream (P-V) */
    uint8_t upstream_idx;
    uint8_t reintentos;
    uint32_t enviado_en; /* ms */
    pending_waiters_t waiters;
};

size_t pending_mem_size(void)
{
    return PENDING_ENTRIES * sizeof(struct pending_entry);
}

void pending_init(pending_table_t *t, void *mem, uint16_t (*rand16)(void))
{
    if (t == NULL || mem == NULL || rand16 == NULL) {
        return;
    }
    t->entries = (struct pending_entry *)mem;
    memset(mem, 0, pending_mem_size());
    t->rand16 = rand16;
    memset(&t->entrega, 0, sizeof(t->entrega));
    t->overflow = 0;
}

/* txid aleatorio garantizado único entre las entradas activas */
static uint16_t txid_unico(const pending_table_t *t)
{
    uint16_t cand = t->rand16();
    for (int intento = 0; intento <= PENDING_ENTRIES; intento++) {
        bool choca = false;
        for (int i = 0; i < PENDING_ENTRIES; i++) {
            if (t->entries[i].en_uso && t->entries[i].txid == cand) {
                choca = true;
                break;
            }
        }
        if (!choca) {
            return cand;
        }
        cand++;
    }
    return cand; /* inalcanzable: 64 entradas < 65 candidatos */
}

static bool misma_clave(const struct pending_entry *e, const dns_query_t *q)
{
    return e->en_uso && e->qname_len == q->qname_len && e->qtype == q->qtype &&
           e->qclass == q->qclass &&
           memcmp(e->qname, q->qname, q->qname_len) == 0;
}

static void copia_waiter(pending_waiter_t *w, const dns_query_t *q)
{
    w->addr = q->client_addr;
    w->port = q->client_port;
    w->id_original = q->id;
    w->transport = q->transport;
    w->edns_present = q->edns_present;
    w->edns_payload = q->edns_payload;
}

static void rellena_entrada(struct pending_entry *e, const dns_query_t *q,
                            uint8_t upstream_idx, uint32_t now_ms, uint16_t txid)
{
    e->en_uso = true;
    memcpy(e->qname, q->qname, (size_t)q->qname_len + 1);
    e->qname_len = q->qname_len;
    e->qtype = q->qtype;
    e->qclass = q->qclass;
    e->txid = txid;
    e->upstream_idx = upstream_idx;
    e->reintentos = 0;
    e->enviado_en = now_ms;
    e->waiters.count = 1;
    copia_waiter(&e->waiters.w[0], q);
}

pending_verdict_t pending_register(pending_table_t *t, const dns_query_t *q,
                                   uint8_t upstream_idx, uint32_t now_ms,
                                   uint16_t *txid_out)
{
    if (t == NULL || t->entries == NULL || q == NULL || txid_out == NULL) {
        return PENDING_SEND_SOLO; /* sin tabla: enviar igualmente (P-I) */
    }
    bool solo = false;
    struct pending_entry *e = NULL;
    struct pending_entry *libre = NULL;
    struct pending_entry *mas_antigua = NULL;
    for (int i = 0; i < PENDING_ENTRIES; i++) {
        struct pending_entry *s = &t->entries[i];
        if (e == NULL && misma_clave(s, q)) {
            e = s; /* sin break: libre/mas_antigua se calculan sobre toda la
                    * tabla (y excluyen a la entrada coincidente) */
            continue;
        }
        if (!s->en_uso) {
            if (libre == NULL) {
                libre = s;
            }
        } else if (mas_antigua == NULL ||
                   (int32_t)(s->enviado_en - mas_antigua->enviado_en) < 0) {
            mas_antigua = s;
        }
    }
    if (e != NULL) {
        if (e->waiters.count < PENDING_WAITERS) {
            copia_waiter(&e->waiters.w[e->waiters.count++], q);
            *txid_out = e->txid;
            return PENDING_GROUPED;
        }
        solo = true; /* waiters lleno: entrada propia, sin agrupar (R5) */
        e = NULL;
    }
    if (libre != NULL) {
        e = libre;
    } else {
        /* tabla llena: desalojar la más antigua — NUNCA dejar de enviar */
        e = mas_antigua;
        t->overflow++;
        solo = true;
    }
    uint16_t txid = txid_unico(t);
    rellena_entrada(e, q, upstream_idx, now_ms, txid);
    *txid_out = txid;
    return solo ? PENDING_SEND_SOLO : PENDING_SEND;
}

/*
 * Extrae la pregunta de una respuesta upstream (eco de nuestra consulta:
 * etiquetas planas, sin compresión) en minúsculas. false si es inválida.
 */
static bool pregunta_de_respuesta(const uint8_t *resp, size_t len,
                                  char nombre[ESPHOLE_DOMAIN_MAX + 1],
                                  uint8_t *nlen, uint16_t *qtype, uint16_t *qclass)
{
    if (resp == NULL || len < 12) {
        return false;
    }
    uint16_t qd = (uint16_t)((resp[4] << 8) | resp[5]);
    if (qd != 1) {
        return false;
    }
    size_t pos = 12;
    size_t w = 0;
    for (;;) {
        if (pos >= len) {
            return false;
        }
        uint8_t lab = resp[pos++];
        if (lab == 0) {
            break;
        }
        if ((lab & 0xC0) != 0 || pos + lab > len) {
            return false;
        }
        size_t need = (w == 0) ? lab : (size_t)lab + 1;
        if (w + need > ESPHOLE_DOMAIN_MAX) {
            return false;
        }
        if (w != 0) {
            nombre[w++] = '.';
        }
        for (uint8_t i = 0; i < lab; i++) {
            uint8_t c = resp[pos + i];
            if (c >= 'A' && c <= 'Z') {
                c = (uint8_t)(c - 'A' + 'a');
            }
            nombre[w++] = (char)c;
        }
        pos += lab;
    }
    if (w == 0 || pos + 4 > len) {
        return false;
    }
    nombre[w] = '\0';
    *nlen = (uint8_t)w;
    *qtype = (uint16_t)((resp[pos] << 8) | resp[pos + 1]);
    *qclass = (uint16_t)((resp[pos + 2] << 8) | resp[pos + 3]);
    return true;
}

const pending_waiters_t *pending_match(pending_table_t *t, uint16_t txid,
                                       const uint8_t *resp, size_t len)
{
    if (t == NULL || t->entries == NULL) {
        return NULL;
    }
    struct pending_entry *e = NULL;
    for (int i = 0; i < PENDING_ENTRIES; i++) {
        if (t->entries[i].en_uso && t->entries[i].txid == txid) {
            e = &t->entries[i];
            break;
        }
    }
    if (e == NULL) {
        return NULL; /* txid desconocido: descartar (CB-44) */
    }
    /* anti-poisoning: la pregunta de la respuesta debe casar con la clave */
    char nombre[ESPHOLE_DOMAIN_MAX + 1];
    uint8_t nlen;
    uint16_t qtype, qclass;
    if (!pregunta_de_respuesta(resp, len, nombre, &nlen, &qtype, &qclass) ||
        nlen != e->qname_len || qtype != e->qtype || qclass != e->qclass ||
        memcmp(nombre, e->qname, nlen) != 0) {
        return NULL; /* la entrada sigue viva esperando la legítima */
    }
    t->entrega = e->waiters;
    memcpy(t->entrega.qname, e->qname, (size_t)e->qname_len + 1);
    t->entrega.qname_len = e->qname_len;
    t->entrega.qtype = e->qtype;
    t->entrega.qclass = e->qclass;
    t->entrega.enviado_en = e->enviado_en;
    e->en_uso = false;
    return &t->entrega;
}

bool pending_upstream_of(const pending_table_t *t, uint16_t txid,
                         uint8_t *idx_out)
{
    if (t == NULL || t->entries == NULL || idx_out == NULL) {
        return false;
    }
    for (int i = 0; i < PENDING_ENTRIES; i++) {
        if (t->entries[i].en_uso && t->entries[i].txid == txid) {
            *idx_out = t->entries[i].upstream_idx;
            return true;
        }
    }
    return false;
}

size_t pending_expire(pending_table_t *t, uint32_t now_ms, uint32_t timeout_ms,
                      pending_action_t *actions, size_t actions_cap)
{
    if (t == NULL || t->entries == NULL || actions == NULL) {
        return 0;
    }
    size_t n = 0;
    for (int i = 0; i < PENDING_ENTRIES && n < actions_cap; i++) {
        struct pending_entry *e = &t->entries[i];
        if (!e->en_uso || (uint32_t)(now_ms - e->enviado_en) < timeout_ms) {
            continue;
        }
        pending_action_t *a = &actions[n++];
        memcpy(a->qname, e->qname, (size_t)e->qname_len + 1);
        a->qname_len = e->qname_len;
        a->qtype = e->qtype;
        a->qclass = e->qclass;
        if (e->reintentos == 0) {
            /* primer vencimiento: reintento hacia el siguiente upstream */
            e->reintentos = 1;
            e->txid = txid_unico(t);
            e->enviado_en = now_ms;
            e->upstream_idx++;
            a->kind = PENDING_ACT_RETRY;
            a->new_txid = e->txid;
            a->upstream_idx = e->upstream_idx;
            memset(&a->waiters, 0, sizeof(a->waiters));
        } else {
            /* agotado: SERVFAIL a todos los que esperan (FR-008) */
            a->kind = PENDING_ACT_FAIL;
            a->new_txid = 0;
            a->upstream_idx = e->upstream_idx;
            a->waiters = e->waiters;
            e->en_uso = false;
        }
    }
    return n;
}
