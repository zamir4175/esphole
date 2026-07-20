/*
 * Helpers compartidos para construir mensajes DNS wire a mano en los tests.
 * static inline para poder incluirse desde varios tests sin warnings.
 */
#ifndef WIRE_HELPERS_H
#define WIRE_HELPERS_H

#include <string.h>

#include "esphole_types.h"

typedef struct {
    uint8_t b[512];
    size_t len;
} pkt_t;

static inline void p8(pkt_t *p, uint8_t v) { p->b[p->len++] = v; }

static inline void p16(pkt_t *p, uint16_t v)
{
    p8(p, (uint8_t)(v >> 8));
    p8(p, (uint8_t)(v & 0xFF));
}

static inline void p32(pkt_t *p, uint32_t v)
{
    p16(p, (uint16_t)(v >> 16));
    p16(p, (uint16_t)(v & 0xFFFF));
}

static inline uint16_t rd16at(const uint8_t *b, size_t off)
{
    return (uint16_t)(((uint16_t)b[off] << 8) | b[off + 1]);
}

static inline uint32_t rd32at(const uint8_t *b, size_t off)
{
    return ((uint32_t)rd16at(b, off) << 16) | rd16at(b, off + 2);
}

static inline void pheader(pkt_t *p, uint16_t id, uint16_t flags, uint16_t qd,
                           uint16_t an, uint16_t ns, uint16_t ar)
{
    p16(p, id);
    p16(p, flags);
    p16(p, qd);
    p16(p, an);
    p16(p, ns);
    p16(p, ar);
}

/* nombre wire desde forma con puntos */
static inline void pname(pkt_t *p, const char *dotted)
{
    const char *s = dotted;
    while (*s != '\0') {
        const char *dot = strchr(s, '.');
        size_t lab = (dot != NULL) ? (size_t)(dot - s) : strlen(s);
        p8(p, (uint8_t)lab);
        memcpy(p->b + p->len, s, lab);
        p->len += lab;
        s += lab;
        if (*s == '.') {
            s++;
        }
    }
    p8(p, 0);
}

static inline void popt(pkt_t *p, uint16_t payload)
{
    p8(p, 0); /* raíz */
    p16(p, DNS_TYPE_OPT);
    p16(p, payload); /* class = payload UDP */
    p32(p, 0);       /* "TTL" = flags extendidos */
    p16(p, 0);       /* RDLENGTH */
}

/* registro con nombre comprimido apuntando a la pregunta (0xC00C) */
static inline void precord(pkt_t *p, uint16_t rtype, uint32_t ttl,
                           const uint8_t *rdata, uint16_t rdlen)
{
    p16(p, 0xC00C);
    p16(p, rtype);
    p16(p, DNS_CLASS_IN);
    p32(p, ttl);
    p16(p, rdlen);
    if (rdlen > 0) {
        memcpy(p->b + p->len, rdata, rdlen);
        p->len += rdlen;
    }
}

static inline pkt_t consulta(const char *name, uint16_t qtype)
{
    pkt_t p = {.len = 0};
    pheader(&p, 0x1234, 0x0100 /* RD */, 1, 0, 0, 0);
    pname(&p, name);
    p16(&p, qtype);
    p16(&p, DNS_CLASS_IN);
    return p;
}

#endif /* WIRE_HELPERS_H */
