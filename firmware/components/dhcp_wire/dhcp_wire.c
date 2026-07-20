#include "dhcp_wire.h"

#include <string.h>

#define DHCP_COOKIE_0 0x63
#define DHCP_COOKIE_1 0x82
#define DHCP_COOKIE_2 0x53
#define DHCP_COOKIE_3 0x63
#define OPT_OFFSET 240

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool dhcp_parse(const uint8_t *pkt, size_t len, dhcp_request_t *out)
{
    if (pkt == NULL || out == NULL || len < DHCP_MIN_LEN) {
        return false;
    }
    if (pkt[0] != 1 || pkt[2] != DHCP_MAC_LEN) {
        return false; /* op != BOOTREQUEST o hlen != 6 */
    }
    if (pkt[236] != DHCP_COOKIE_0 || pkt[237] != DHCP_COOKIE_1 ||
        pkt[238] != DHCP_COOKIE_2 || pkt[239] != DHCP_COOKIE_3) {
        return false; /* sin cookie mágica */
    }
    memset(out, 0, sizeof(*out));
    out->xid = rd32(pkt + 4);
    out->flags = (uint16_t)(((uint16_t)pkt[10] << 8) | pkt[11]);
    out->ciaddr = rd32(pkt + 12);
    memcpy(out->mac, pkt + 28, DHCP_MAC_LEN);

    /* opciones TLV desde 240, acotadas a len */
    size_t i = OPT_OFFSET;
    while (i < len) {
        uint8_t code = pkt[i++];
        if (code == 0) {
            continue; /* pad */
        }
        if (code == 255) {
            break; /* fin */
        }
        if (i >= len) {
            break; /* falta el byte de longitud */
        }
        uint8_t olen = pkt[i++];
        if (i + olen > len) {
            break; /* la opción se sale de len: cortar sin leer fuera de rango */
        }
        const uint8_t *val = pkt + i;
        switch (code) {
        case 53:
            if (olen >= 1) {
                out->msgtype = val[0];
            }
            break;
        case 50:
            if (olen == 4) {
                out->requested_ip = rd32(val);
            }
            break;
        case 54:
            if (olen == 4) {
                out->server_id = rd32(val);
            }
            break;
        case 12: {
            size_t n = (olen < sizeof(out->hostname) - 1) ? olen
                                                          : sizeof(out->hostname) - 1;
            memcpy(out->hostname, val, n);
            out->hostname[n] = '\0';
            break;
        }
        default:
            break;
        }
        i += olen;
    }
    return true;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

size_t dhcp_build(const dhcp_reply_t *r, uint8_t *out, size_t cap)
{
    if (r == NULL || out == NULL || r->mac == NULL || cap < DHCP_MIN_LEN) {
        return 0;
    }
    memset(out, 0, DHCP_MIN_LEN);
    out[0] = 2; /* BOOTREPLY */
    out[1] = 1; /* htype Ethernet */
    out[2] = DHCP_MAC_LEN;
    wr32(out + 4, r->xid);
    out[10] = (uint8_t)(r->flags >> 8);
    out[11] = (uint8_t)r->flags;
    wr32(out + 16, r->yiaddr); /* yiaddr */
    memcpy(out + 28, r->mac, DHCP_MAC_LEN);
    out[236] = DHCP_COOKIE_0;
    out[237] = DHCP_COOKIE_1;
    out[238] = DHCP_COOKIE_2;
    out[239] = DHCP_COOKIE_3;

    size_t i = OPT_OFFSET;
#define NEED(n)                                                                \
    do {                                                                       \
        if (i + (n) > cap) {                                                   \
            return 0;                                                          \
        }                                                                      \
    } while (0)
    NEED(3);
    out[i++] = 53;
    out[i++] = 1;
    out[i++] = r->msgtype;
    NEED(6);
    out[i++] = 54;
    out[i++] = 4;
    wr32(out + i, r->server_id);
    i += 4;
    if (r->msgtype != DHCP_NAK) {
        NEED(6);
        out[i++] = 1; /* subnet mask */
        out[i++] = 4;
        wr32(out + i, r->mask);
        i += 4;
        NEED(6);
        out[i++] = 3; /* router / gateway */
        out[i++] = 4;
        wr32(out + i, r->gateway);
        i += 4;
        NEED(6);
        out[i++] = 6; /* DNS = ESPHole */
        out[i++] = 4;
        wr32(out + i, r->dns);
        i += 4;
        NEED(6);
        out[i++] = 51; /* lease time */
        out[i++] = 4;
        wr32(out + i, r->lease_time);
        i += 4;
    }
    NEED(1);
    out[i++] = 255; /* fin */
#undef NEED
    return i;
}
