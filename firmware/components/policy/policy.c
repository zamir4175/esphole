#include "policy.h"

#include <string.h>

bool policy_is_local(const policy_t *p, const ip_addr16_t *src)
{
    if (p == NULL || src == NULL) {
        return false;
    }
    uint8_t max_bits = (src->family == ESPHOLE_AF_V4) ? 32 : 128;
    for (uint8_t i = 0; i < p->count && i < 4; i++) {
        const subnet_t *s = &p->subnets[i];
        if (s->base.family != src->family || s->prefix_len > max_bits) {
            continue;
        }
        uint8_t bytes_enteros = s->prefix_len / 8;
        uint8_t bits_resto = s->prefix_len % 8;
        if (memcmp(s->base.bytes, src->bytes, bytes_enteros) != 0) {
            continue;
        }
        if (bits_resto != 0) {
            uint8_t mascara = (uint8_t)(0xFF << (8 - bits_resto));
            if ((s->base.bytes[bytes_enteros] & mascara) !=
                (src->bytes[bytes_enteros] & mascara)) {
                continue;
            }
        }
        return true;
    }
    return false;
}

policy_action_t policy_on_datapath_error(dns_wire_err_t err)
{
    /* Único punto de decisión del camino rápido (P-I): SOLO lo malformado se
     * descarta; cualquier otro error degrada a reenvío íntegro. */
    return (err == DNS_WIRE_MALFORMED) ? POLICY_DROP : POLICY_FORWARD;
}
