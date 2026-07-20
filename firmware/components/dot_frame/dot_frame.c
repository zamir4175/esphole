/*
 * dot_frame — framing DoT (RFC 7858) y validación de respuesta (PURO).
 * Contrato: specs/007-dot-upstream/contracts/dot-frame.md (DF-01..08).
 * El parser de dns_wire exige QR=0 (consulta), así que no vale para validar una
 * respuesta: aquí se hace un recorrido de etiquetas acotado y autocontenido.
 */
#include "dot_frame.h"

/* tolower ASCII sin locale (evita <ctype.h> y su dependencia de locale). */
static uint8_t lc(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/*
 * Fin (exclusivo) de la sección de pregunta de un mensaje DNS de 'len' bytes:
 * cabecera (12) + QNAME (etiquetas 1..63, sin punteros de compresión) + qtype(2)
 * + qclass(2). Devuelve el offset tras qclass, o 0 si algo se sale del buffer o
 * está malformado. Solo lee dentro de [buf, buf+len).
 */
static size_t question_end(const uint8_t *buf, size_t len)
{
    if (len < 12) {
        return 0;
    }
    size_t p = 12;
    for (;;) {
        if (p >= len) {
            return 0;
        }
        uint8_t c = buf[p];
        if (c == 0) {
            p++; /* octeto de fin de nombre */
            break;
        }
        if (c & 0xc0) {
            return 0; /* puntero de compresión: prohibido en la pregunta */
        }
        p += (size_t)1 + c; /* longitud + etiqueta */
    }
    if (p + 4 > len) {
        return 0; /* qtype + qclass */
    }
    return p + 4;
}

size_t dot_frame_prefix(const uint8_t *msg, size_t len, uint8_t *out, size_t cap)
{
    if (len > 0xffff || len + 2 > cap) {
        return 0;
    }
    out[0] = (uint8_t)(len >> 8);
    out[1] = (uint8_t)(len & 0xff);
    for (size_t i = 0; i < len; i++) {
        out[2 + i] = msg[i];
    }
    return len + 2;
}

bool dot_response_ok(const uint8_t *query, size_t qlen, const uint8_t *resp,
                     size_t rlen)
{
    if (qlen < 12 || rlen < 12) {
        return false;
    }
    /* la respuesta debe tener el bit QR (byte 2, bit alto) */
    if ((resp[2] & 0x80) == 0) {
        return false;
    }
    /* mismo id de transacción (bytes 0-1) */
    if (query[0] != resp[0] || query[1] != resp[1]) {
        return false;
    }
    /* misma sección de pregunta (qname/qtype/qclass) */
    size_t qend = question_end(query, qlen);
    size_t rend = question_end(resp, rlen);
    if (qend == 0 || rend == 0) {
        return false;
    }
    if (qend != rend) {
        return false; /* longitudes de pregunta distintas ⇒ no casa */
    }
    for (size_t i = 12; i < qend; i++) {
        if (lc(query[i]) != lc(resp[i])) {
            return false; /* qname (case-insensitive) / qtype / qclass */
        }
    }
    return true;
}
