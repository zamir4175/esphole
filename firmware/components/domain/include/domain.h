/*
 * domain — normalización, inversión y coincidencia por sufijo (PURO).
 * Contrato: specs/001-servicio-dns-core/contracts/module-interfaces.md §2.
 */
#ifndef ESPHOLE_DOMAIN_H
#define ESPHOLE_DOMAIN_H

#include "esphole_types.h"

/*
 * Normaliza (minúsculas; charset [a-z0-9_-] por etiqueta; etiquetas 1..63;
 * total ≤253; admite punto final) e invierte las etiquetas:
 * "Ads.Example.COM" → "com.example.ads".
 * Devuelve la longitud escrita en out (NUL-terminado), o -1 si es inválido.
 */
int domain_normalize_invert(const char *name, size_t name_len,
                            char out[ESPHOLE_DOMAIN_MAX + 1]);

/*
 * Coincidencia por sufijo consciente de etiquetas sobre nombres YA invertidos
 * (FR-015): entry="com.example" casa con "com.example" y "com.example.ads",
 * nunca con "com.examplebad". Entrada vacía no casa con nada.
 */
bool domain_suffix_match(const char *inverted_entry, size_t entry_len,
                         const char *inverted_candidate, size_t candidate_len);

#endif /* ESPHOLE_DOMAIN_H */
