#include "dns_wire.h"

#include <string.h>

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/*
 * Salta un nombre en formato wire (etiquetas o puntero de compresión) sin
 * decodificarlo. Devuelve false si desborda el mensaje.
 */
static bool skip_name(const uint8_t *buf, size_t len, size_t *pos)
{
    size_t p = *pos;
    for (;;) {
        if (p >= len) {
            return false;
        }
        uint8_t lab = buf[p];
        if (lab == 0) {
            p++;
            break;
        }
        if ((lab & 0xC0) == 0xC0) { /* puntero: 2 bytes y el nombre termina */
            if (p + 2 > len) {
                return false;
            }
            p += 2;
            break;
        }
        if ((lab & 0xC0) != 0) { /* bits 10/01: reservados */
            return false;
        }
        p += 1u + lab;
    }
    *pos = p;
    return true;
}

dns_wire_err_t dns_wire_parse_query(const uint8_t *buf, size_t len, dns_query_t *out)
{
    if (buf == NULL || out == NULL || len < 12 || len > UINT16_MAX) {
        return DNS_WIRE_MALFORMED;
    }
    memset(out, 0, sizeof(*out));
    /* id/flags/raw se rellenan ya: los retornos UNSUPPORTED también los
     * necesitan (el passthrough responde con el ID del cliente, FR-006) */
    out->id = rd16(buf);
    out->raw = buf;
    out->raw_len = (uint16_t)len;

    uint16_t flags = rd16(buf + 2);
    uint16_t qd = rd16(buf + 4);
    uint16_t an = rd16(buf + 6);
    uint16_t ns = rd16(buf + 8);
    uint16_t ar = rd16(buf + 10);

    if ((flags & 0x8000) != 0) { /* QR=1: una respuesta no es una consulta */
        return DNS_WIRE_MALFORMED;
    }
    if (((flags >> 11) & 0xF) != 0) { /* OPCODE ≠ QUERY */
        return DNS_WIRE_UNSUPPORTED;
    }
    if (qd != 1) {
        return DNS_WIRE_UNSUPPORTED;
    }

    /* QNAME: etiquetas planas; punteros de compresión no son válidos en la
     * pregunta de un cliente. Se normaliza a minúsculas en presentación. */
    size_t pos = 12;
    size_t w = 0;
    for (;;) {
        if (pos >= len) {
            return DNS_WIRE_MALFORMED;
        }
        uint8_t lab = buf[pos++];
        if (lab == 0) {
            break;
        }
        if ((lab & 0xC0) != 0) {
            return DNS_WIRE_MALFORMED;
        }
        if (pos + lab > len) {
            return DNS_WIRE_MALFORMED;
        }
        size_t need = (w == 0) ? lab : (size_t)lab + 1;
        if (w + need > ESPHOLE_DOMAIN_MAX) {
            return DNS_WIRE_MALFORMED;
        }
        if (w != 0) {
            out->qname[w++] = '.';
        }
        for (uint8_t i = 0; i < lab; i++) {
            uint8_t c = buf[pos + i];
            /* bytes no imprimibles son DNS legal pero jamás estarán en una
             * lista: se reenvía íntegra sin procesar (y qname sigue siendo
             * una cadena C válida) */
            if (c < 33 || c > 126) {
                return DNS_WIRE_UNSUPPORTED;
            }
            if (c >= 'A' && c <= 'Z') {
                c = (uint8_t)(c - 'A' + 'a');
            }
            out->qname[w++] = (char)c;
        }
        pos += lab;
    }
    if (w == 0) { /* consulta por la raíz: reenviar íntegra */
        return DNS_WIRE_UNSUPPORTED;
    }
    out->qname[w] = '\0';
    out->qname_len = (uint8_t)w;

    if (pos + 4 > len) {
        return DNS_WIRE_MALFORMED;
    }
    out->qtype = rd16(buf + pos);
    out->qclass = rd16(buf + pos + 2);
    pos += 4;
    out->question_end = (uint16_t)pos;

    /* Recorre los registros restantes (normalmente solo additionals) buscando
     * el OPT (RFC 6891). Más de un OPT es malformado. */
    uint32_t registros = (uint32_t)an + ns + ar;
    for (uint32_t r = 0; r < registros; r++) {
        if (!skip_name(buf, len, &pos)) {
            return DNS_WIRE_MALFORMED;
        }
        if (pos + 10 > len) {
            return DNS_WIRE_MALFORMED;
        }
        uint16_t rtype = rd16(buf + pos);
        uint16_t rclass = rd16(buf + pos + 2);
        uint16_t rdlen = rd16(buf + pos + 8);
        pos += 10;
        if (pos + rdlen > len) {
            return DNS_WIRE_MALFORMED;
        }
        pos += rdlen;
        if (rtype == DNS_TYPE_OPT) {
            if (out->edns_present) {
                return DNS_WIRE_MALFORMED;
            }
            out->edns_present = true;
            out->edns_payload = rclass;
        }
    }

    out->flags = flags;
    return DNS_WIRE_OK;
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void wr32(uint8_t *p, uint32_t v)
{
    wr16(p, (uint16_t)(v >> 16));
    wr16(p + 2, (uint16_t)(v & 0xFFFF));
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)rd16(p) << 16) | rd16(p + 2);
}

/*
 * Cabecera de respuesta + eco byte a byte de la pregunta original (preserva el
 * casing del cliente: dns0x20). Devuelve question_end o 0 si no cabe.
 */
static size_t emit_reply_base(const dns_query_t *q, uint8_t rcode, uint16_t ancount,
                              uint8_t *buf, size_t buf_cap)
{
    if (q == NULL || q->raw == NULL || buf == NULL) {
        return 0;
    }
    size_t qend = q->question_end;
    if (qend < 17 || qend > q->raw_len || buf_cap < qend) {
        return 0;
    }
    memcpy(buf, q->raw, qend);
    /* QR=1 AA=1 TC=0, RD del cliente; RA=1 + RCODE */
    buf[2] = (uint8_t)(0x80 | 0x04 | (uint8_t)((q->flags >> 8) & 0x01));
    buf[3] = (uint8_t)(0x80 | (rcode & 0x0F));
    wr16(buf + 4, 1);       /* QDCOUNT */
    wr16(buf + 6, ancount);
    wr16(buf + 8, 0);       /* NSCOUNT */
    wr16(buf + 10, 0);      /* ARCOUNT: se ajusta si se añade OPT */
    return qend;
}

/* OPT propio al final de la respuesta; actualiza ARCOUNT. 0 si no cabe. */
static size_t append_opt(uint8_t *buf, size_t pos, size_t buf_cap)
{
    if (pos + 11 > buf_cap) {
        return 0;
    }
    buf[pos] = 0; /* raíz */
    wr16(buf + pos + 1, DNS_TYPE_OPT);
    wr16(buf + pos + 3, DNS_WIRE_OUR_EDNS_PAYLOAD);
    wr32(buf + pos + 5, 0);
    wr16(buf + pos + 9, 0);
    wr16(buf + 10, 1);
    return pos + 11;
}

size_t dns_wire_build_block_response(const dns_query_t *q, uint32_t block_ttl,
                                     uint8_t *buf, size_t buf_cap)
{
    if (q == NULL) {
        return 0;
    }
    bool con_datos = (q->qtype == DNS_TYPE_A || q->qtype == DNS_TYPE_AAAA);
    size_t pos = emit_reply_base(q, DNS_RCODE_NOERROR, con_datos ? 1 : 0, buf, buf_cap);
    if (pos == 0) {
        return 0;
    }
    if (con_datos) {
        uint16_t rdlen = (q->qtype == DNS_TYPE_A) ? 4 : 16;
        if (pos + 12u + rdlen > buf_cap) {
            return 0;
        }
        wr16(buf + pos, 0xC00C); /* puntero al nombre de la pregunta */
        wr16(buf + pos + 2, q->qtype);
        wr16(buf + pos + 4, DNS_CLASS_IN);
        wr32(buf + pos + 6, block_ttl);
        wr16(buf + pos + 10, rdlen);
        memset(buf + pos + 12, 0, rdlen); /* 0.0.0.0 / :: */
        pos += 12u + rdlen;
    }
    if (q->edns_present) {
        pos = append_opt(buf, pos, buf_cap);
    }
    return pos;
}

size_t dns_wire_build_rcode_response(const dns_query_t *q, uint8_t rcode,
                                     uint8_t *buf, size_t buf_cap)
{
    size_t pos = emit_reply_base(q, rcode, 0, buf, buf_cap);
    if (pos == 0) {
        return 0;
    }
    if (q->edns_present) {
        pos = append_opt(buf, pos, buf_cap);
    }
    return pos;
}

size_t dns_wire_build_a_response(const dns_query_t *q, const uint8_t ip[4],
                                 uint32_t ttl, uint8_t *buf, size_t buf_cap)
{
    if (q == NULL || ip == NULL) {
        return 0;
    }
    bool con_datos = (q->qtype == DNS_TYPE_A); /* el cautivo solo captura A */
    size_t pos = emit_reply_base(q, DNS_RCODE_NOERROR, con_datos ? 1 : 0, buf,
                                 buf_cap);
    if (pos == 0) {
        return 0;
    }
    if (con_datos) {
        if (pos + 16 > buf_cap) {
            return 0;
        }
        wr16(buf + pos, 0xC00C); /* puntero al nombre de la pregunta */
        wr16(buf + pos + 2, DNS_TYPE_A);
        wr16(buf + pos + 4, DNS_CLASS_IN);
        wr32(buf + pos + 6, ttl);
        wr16(buf + pos + 10, 4);
        memcpy(buf + pos + 12, ip, 4);
        pos += 16;
    }
    if (q->edns_present) {
        pos = append_opt(buf, pos, buf_cap);
    }
    return pos;
}

void dns_wire_rewrite_id(uint8_t *resp, size_t len, uint16_t new_id)
{
    if (resp != NULL && len >= 2) {
        wr16(resp, new_id);
    }
}

/*
 * Recorre un mensaje wire: deja *pos al final de la sección de preguntas y
 * devuelve los contadores. false si la estructura es inválida.
 */
static bool walk_questions(const uint8_t *buf, size_t len, size_t *pos,
                           uint16_t *an, uint16_t *ns, uint16_t *ar)
{
    if (buf == NULL || len < 12) {
        return false;
    }
    uint16_t qd = rd16(buf + 4);
    *an = rd16(buf + 6);
    *ns = rd16(buf + 8);
    *ar = rd16(buf + 10);
    size_t p = 12;
    for (uint16_t i = 0; i < qd; i++) {
        if (!skip_name(buf, len, &p) || p + 4 > len) {
            return false;
        }
        p += 4;
    }
    *pos = p;
    return true;
}

/* Avanza sobre un registro; expone tipo y offset del TTL. */
static bool walk_record(const uint8_t *buf, size_t len, size_t *pos,
                        uint16_t *rtype, size_t *ttl_off)
{
    if (!skip_name(buf, len, pos) || *pos + 10 > len) {
        return false;
    }
    *rtype = rd16(buf + *pos);
    *ttl_off = *pos + 4;
    uint16_t rdlen = rd16(buf + *pos + 8);
    *pos += 10;
    if (*pos + rdlen > len) {
        return false;
    }
    *pos += rdlen;
    return true;
}

bool dns_wire_min_ttl(const uint8_t *resp, size_t len, uint32_t *ttl_out)
{
    size_t pos;
    uint16_t an, ns, ar;
    if (ttl_out == NULL || !walk_questions(resp, len, &pos, &an, &ns, &ar)) {
        return false;
    }
    if (an > 0) {
        uint32_t min = UINT32_MAX;
        for (uint16_t i = 0; i < an; i++) {
            uint16_t rtype;
            size_t toff;
            if (!walk_record(resp, len, &pos, &rtype, &toff)) {
                return false;
            }
            uint32_t ttl = rd32(resp + toff);
            if (ttl < min) {
                min = ttl;
            }
        }
        *ttl_out = min;
        return true;
    }
    /* caché negativa: TTL del SOA en authority (RFC 2308) */
    for (uint16_t i = 0; i < ns; i++) {
        uint16_t rtype;
        size_t toff;
        if (!walk_record(resp, len, &pos, &rtype, &toff)) {
            return false;
        }
        if (rtype == DNS_TYPE_SOA) {
            *ttl_out = rd32(resp + toff);
            return true;
        }
    }
    return false;
}

dns_wire_err_t dns_wire_decrement_ttls(uint8_t *resp, size_t len, uint32_t elapsed)
{
    size_t pos;
    uint16_t an, ns, ar;
    if (!walk_questions(resp, len, &pos, &an, &ns, &ar)) {
        return DNS_WIRE_MALFORMED;
    }
    uint32_t total = (uint32_t)an + ns + ar;
    for (uint32_t i = 0; i < total; i++) {
        uint16_t rtype;
        size_t toff;
        if (!walk_record(resp, len, &pos, &rtype, &toff)) {
            return DNS_WIRE_MALFORMED;
        }
        if (rtype == DNS_TYPE_OPT) { /* su "TTL" son flags: no tocar */
            continue;
        }
        uint32_t ttl = rd32(resp + toff);
        wr32(resp + toff, (ttl > elapsed) ? ttl - elapsed : 0);
    }
    return DNS_WIRE_OK;
}

size_t dns_wire_truncate(uint8_t *resp, size_t len, size_t payload_max)
{
    size_t qend;
    uint16_t an, ns, ar;
    if (!walk_questions(resp, len, &qend, &an, &ns, &ar)) {
        return 0;
    }
    bool habia_opt = false;
    size_t pos = qend;
    uint32_t total = (uint32_t)an + ns + ar;
    for (uint32_t i = 0; i < total; i++) {
        uint16_t rtype;
        size_t toff;
        if (!walk_record(resp, len, &pos, &rtype, &toff)) {
            return 0;
        }
        if (rtype == DNS_TYPE_OPT) {
            habia_opt = true;
        }
    }
    resp[2] |= 0x02; /* TC */
    wr16(resp + 6, 0);
    wr16(resp + 8, 0);
    wr16(resp + 10, 0);
    size_t fin = qend;
    if (habia_opt) {
        fin = append_opt(resp, qend, len);
        if (fin == 0) {
            return 0;
        }
    }
    return (fin <= payload_max) ? fin : 0;
}

uint8_t dns_wire_rcode(const uint8_t *msg, size_t len)
{
    if (msg == NULL || len < 4) {
        return 0;
    }
    return msg[3] & 0x0F;
}

size_t dns_wire_build_query(const char *qname, uint8_t qname_len, uint16_t qtype,
                            uint16_t qclass, uint16_t txid, bool with_edns,
                            uint8_t *buf, size_t buf_cap)
{
    if (qname == NULL || buf == NULL || qname_len == 0 ||
        qname_len > ESPHOLE_DOMAIN_MAX) {
        return 0;
    }
    /* wire del nombre = qname_len + 2 (longitud inicial + terminador) */
    size_t need = 12u + qname_len + 2u + 4u + (with_edns ? 11u : 0u);
    if (buf_cap < need) {
        return 0;
    }
    wr16(buf, txid);
    wr16(buf + 2, 0x0100); /* RD=1 */
    wr16(buf + 4, 1);
    wr16(buf + 6, 0);
    wr16(buf + 8, 0);
    wr16(buf + 10, 0);
    size_t pos = 12;
    size_t start = 0;
    for (size_t i = 0; i <= qname_len; i++) {
        if (i == qname_len || qname[i] == '.') {
            size_t lab = i - start;
            if (lab == 0 || lab > ESPHOLE_LABEL_MAX) {
                return 0;
            }
            buf[pos++] = (uint8_t)lab;
            memcpy(buf + pos, qname + start, lab);
            pos += lab;
            start = i + 1;
        }
    }
    buf[pos++] = 0;
    wr16(buf + pos, qtype);
    wr16(buf + pos + 2, qclass);
    pos += 4;
    if (with_edns) {
        pos = append_opt(buf, pos, buf_cap);
    }
    return pos;
}

uint16_t dns_wire_edns_payload(const dns_query_t *q)
{
    if (q == NULL || !q->edns_present) {
        return 512;
    }
    return (q->edns_payload < 512) ? 512 : q->edns_payload;
}
