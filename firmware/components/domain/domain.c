#include "domain.h"

#include <string.h>

int domain_normalize_invert(const char *name, size_t name_len,
                            char out[ESPHOLE_DOMAIN_MAX + 1])
{
    if (name == NULL || out == NULL) {
        return -1;
    }
    if (name_len > 0 && name[name_len - 1] == '.') {
        name_len--; /* punto final FQDN */
    }
    if (name_len == 0 || name_len > ESPHOLE_DOMAIN_MAX) {
        return -1;
    }

    /* Recorre las etiquetas de derecha a izquierda copiándolas normalizadas. */
    size_t w = 0;
    size_t end = name_len; /* fin exclusivo de la etiqueta actual */
    for (;;) {
        size_t start = end;
        while (start > 0 && name[start - 1] != '.') {
            start--;
        }
        size_t lab = end - start;
        if (lab == 0 || lab > ESPHOLE_LABEL_MAX) {
            return -1;
        }
        for (size_t i = 0; i < lab; i++) {
            char c = name[start + i];
            if (c >= 'A' && c <= 'Z') {
                c = (char)(c - 'A' + 'a');
            }
            bool valido = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                          c == '-' || c == '_';
            if (!valido) {
                return -1;
            }
            out[w + i] = c;
        }
        w += lab;
        if (start == 0) {
            break;
        }
        out[w++] = '.';
        end = start - 1; /* salta el separador */
    }
    out[w] = '\0';
    return (int)w;
}

bool domain_suffix_match(const char *inverted_entry, size_t entry_len,
                         const char *inverted_candidate, size_t candidate_len)
{
    if (entry_len == 0 || entry_len > candidate_len) {
        return false;
    }
    if (memcmp(inverted_entry, inverted_candidate, entry_len) != 0) {
        return false;
    }
    /* límite de etiqueta: o son iguales, o lo que sigue es un separador */
    return candidate_len == entry_len || inverted_candidate[entry_len] == '.';
}
