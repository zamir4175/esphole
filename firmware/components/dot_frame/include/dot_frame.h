/*
 * dot_frame — framing DoT (RFC 7858) y validación de respuesta (PURO).
 * Contrato: specs/007-dot-upstream/contracts/dot-frame.md (DF-01..08).
 * Sin ESP-IDF. Toda respuesta del resolvedor se trata como hostil: ningún
 * acceso fuera de los buffers dados.
 */
#ifndef ESPHOLE_DOT_FRAME_H
#define ESPHOLE_DOT_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Antepone el prefijo de 2 bytes (longitud big-endian, RFC 7858) al mensaje DNS:
 * out = [len_hi][len_lo][msg...]. Devuelve len+2, o 0 si no cabe en cap o len
 * no cabe en 16 bits.
 */
size_t dot_frame_prefix(const uint8_t *msg, size_t len, uint8_t *out, size_t cap);

/*
 * ¿la respuesta del resolvedor casa con la consulta enviada? Compara el id de
 * transacción y la sección de pregunta (qname/qtype/qclass). false si algo no
 * casa o si cualquiera está malformado. Solo lee dentro de los buffers dados.
 */
bool dot_response_ok(const uint8_t *query, size_t qlen, const uint8_t *resp,
                     size_t rlen);

#endif /* ESPHOLE_DOT_FRAME_H */
