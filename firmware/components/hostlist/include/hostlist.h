/*
 * hostlist — extracción de dominios de listas HOSTS/planas (PURO). spec 004.
 * Contrato: specs/004-listas-desde-url/contracts/hostlist-logic.md.
 * C11, sin dependencias de ESP-IDF. Toda línea de entrada es hostil.
 */
#ifndef ESPHOLE_HOSTLIST_H
#define ESPHOLE_HOSTLIST_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Extrae el dominio candidato de UNA línea de una lista (formato HOSTS
 * "IP dominio" o lista plana de dominios). No copia: *dom apunta dentro de
 * 'line' y NO queda NUL-terminado (usar *dom_len). Devuelve true si la línea
 * aporta un dominio a considerar; false para ignorar (comentario, vacía o
 * pseudo-dominio de sistema como localhost). La validación de etiquetas y
 * longitud la hace después domain_normalize_invert. Nunca lee fuera de
 * [line, line+len).
 */
bool hostlist_parse_line(const char *line, size_t len, const char **dom,
                         size_t *dom_len);

#endif /* ESPHOLE_HOSTLIST_H */
