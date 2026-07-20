/*
 * Tests host de dhcp_wire (spec 006, contrato DW-01..09).
 * Todo paquete es hostil: corre bajo ASan/UBSan.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "dhcp_wire.h"

void setUp(void) {}
void tearDown(void) {}

static uint8_t PKT[512];
static const uint8_t MAC[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11};

/* cabecera BOOTREQUEST + cookie; devuelve el offset donde empiezan las opciones */
static size_t mk_base(uint32_t xid, const uint8_t mac[6])
{
    memset(PKT, 0, sizeof(PKT));
    PKT[0] = 1; /* op = BOOTREQUEST */
    PKT[1] = 1; /* htype = Ethernet */
    PKT[2] = 6; /* hlen */
    PKT[4] = (uint8_t)(xid >> 24);
    PKT[5] = (uint8_t)(xid >> 16);
    PKT[6] = (uint8_t)(xid >> 8);
    PKT[7] = (uint8_t)xid;
    memcpy(PKT + 28, mac, 6); /* chaddr */
    PKT[236] = 0x63;          /* cookie mágica */
    PKT[237] = 0x82;
    PKT[238] = 0x53;
    PKT[239] = 0x63;
    return 240;
}

static size_t put_opt(size_t pos, uint8_t code, uint8_t len, const uint8_t *val)
{
    PKT[pos++] = code;
    PKT[pos++] = len;
    if (len) {
        memcpy(PKT + pos, val, len);
    }
    return pos + len;
}

static size_t put_end(size_t pos)
{
    PKT[pos++] = 255;
    return pos;
}

/* DW-01: DISCOVER → tipo, mac, xid */
static void test_parse_discover(void)
{
    size_t p = mk_base(0x12345678, MAC);
    uint8_t t = DHCP_DISCOVER;
    p = put_opt(p, 53, 1, &t);
    p = put_end(p);
    dhcp_request_t r;
    TEST_ASSERT_TRUE(dhcp_parse(PKT, p, &r));
    TEST_ASSERT_EQUAL_UINT8(DHCP_DISCOVER, r.msgtype);
    TEST_ASSERT_EQUAL_UINT32(0x12345678, r.xid);
    TEST_ASSERT_EQUAL_MEMORY(MAC, r.mac, 6);
}

/* DW-02: REQUEST con opción 50 (requested) y 54 (server id) */
static void test_parse_request(void)
{
    size_t p = mk_base(0xaabbccdd, MAC);
    uint8_t t = DHCP_REQUEST;
    p = put_opt(p, 53, 1, &t);
    uint8_t reqip[4] = {192, 168, 1, 50};
    p = put_opt(p, 50, 4, reqip);
    uint8_t sid[4] = {192, 168, 1, 1};
    p = put_opt(p, 54, 4, sid);
    p = put_end(p);
    dhcp_request_t r;
    TEST_ASSERT_TRUE(dhcp_parse(PKT, p, &r));
    TEST_ASSERT_EQUAL_UINT8(DHCP_REQUEST, r.msgtype);
    TEST_ASSERT_EQUAL_UINT32(0xC0A80132u, r.requested_ip); /* 192.168.1.50 */
    TEST_ASSERT_EQUAL_UINT32(0xC0A80101u, r.server_id);    /* 192.168.1.1 */
}

/* DW-03: hostname (opción 12) */
static void test_parse_hostname(void)
{
    size_t p = mk_base(1, MAC);
    uint8_t t = DHCP_DISCOVER;
    p = put_opt(p, 53, 1, &t);
    p = put_opt(p, 12, 6, (const uint8_t *)"laptop");
    p = put_end(p);
    dhcp_request_t r;
    TEST_ASSERT_TRUE(dhcp_parse(PKT, p, &r));
    TEST_ASSERT_EQUAL_STRING("laptop", r.hostname);
}

/* DW-04: paquetes inválidos → false */
static void test_parse_invalidos(void)
{
    dhcp_request_t r;
    size_t p = mk_base(1, MAC);
    p = put_end(p);
    /* sin cookie */
    PKT[236] = 0;
    TEST_ASSERT_FALSE(dhcp_parse(PKT, p, &r));
    /* op inválido */
    mk_base(1, MAC);
    PKT[0] = 2; /* BOOTREPLY, no request */
    TEST_ASSERT_FALSE(dhcp_parse(PKT, 240, &r));
    /* demasiado corto */
    mk_base(1, MAC);
    TEST_ASSERT_FALSE(dhcp_parse(PKT, 239, &r));
    /* hlen != 6 */
    mk_base(1, MAC);
    PKT[2] = 8;
    TEST_ASSERT_FALSE(dhcp_parse(PKT, 240, &r));
}

/* DW-05: opción cuya longitud se sale de len → corta sin leer fuera de rango */
static void test_parse_opcion_desbordada(void)
{
    size_t p = mk_base(1, MAC);
    uint8_t t = DHCP_DISCOVER;
    p = put_opt(p, 53, 1, &t);
    /* opción 50 declara len=200 pero solo dejamos 2 bytes antes del fin de 'len' */
    PKT[p++] = 50;
    PKT[p++] = 200; /* miente */
    PKT[p++] = 0xAA;
    PKT[p++] = 0xBB;
    dhcp_request_t r;
    /* no debe leer más allá de p (ASan lo detectaría); parseo válido de lo previo */
    TEST_ASSERT_TRUE(dhcp_parse(PKT, p, &r));
    TEST_ASSERT_EQUAL_UINT8(DHCP_DISCOVER, r.msgtype);
    TEST_ASSERT_EQUAL_UINT32(0, r.requested_ip); /* la opción truncada se ignora */
}

/* DW-09: mini-fuzz — mutaciones de un DISCOVER; nunca lee fuera de rango */
static void test_parse_fuzz(void)
{
    size_t p = mk_base(0x99, MAC);
    uint8_t t = DHCP_DISCOVER;
    p = put_opt(p, 53, 1, &t);
    uint8_t reqip[4] = {10, 0, 0, 5};
    p = put_opt(p, 50, 4, reqip);
    p = put_end(p);
    for (size_t i = 0; i < p; i++) {
        for (int b = 0; b < 256; b += 23) {
            uint8_t *buf = malloc(p);
            memcpy(buf, PKT, p);
            buf[i] = (uint8_t)b;
            dhcp_request_t r;
            dhcp_parse(buf, p, &r); /* no debe desbordar (ASan) */
            /* también con longitudes truncadas */
            dhcp_parse(buf, i + 1, &r);
            free(buf);
        }
    }
}

/* localiza una opción en un paquete construido; devuelve su valor y longitud */
static const uint8_t *find_opt(const uint8_t *buf, size_t len, uint8_t code, uint8_t *olen)
{
    size_t i = 240;
    while (i < len) {
        uint8_t c = buf[i++];
        if (c == 0) continue;
        if (c == 255 || i >= len) break;
        uint8_t l = buf[i++];
        if (i + l > len) break;
        if (c == code) { *olen = l; return buf + i; }
        i += l;
    }
    return NULL;
}

/* DW-06: construir OFFER y verificar cabecera + opciones */
static void test_build_offer(void)
{
    uint8_t out[512];
    dhcp_reply_t r = {
        .msgtype = DHCP_OFFER, .xid = 0x11223344, .flags = 0x8000,
        .yiaddr = 0xC0A80164u /* 192.168.1.100 */, .mac = MAC,
        .server_id = 0xC0A80101u, .mask = 0xFFFFFF00u,
        .gateway = 0xC0A801FEu, .dns = 0xC0A80101u, .lease_time = 3600,
    };
    size_t n = dhcp_build(&r, out, sizeof(out));
    TEST_ASSERT_TRUE(n >= 240);
    TEST_ASSERT_EQUAL_UINT8(2, out[0]);            /* BOOTREPLY */
    TEST_ASSERT_EQUAL_UINT8(1, out[1]);            /* htype */
    TEST_ASSERT_EQUAL_UINT8(6, out[2]);            /* hlen */
    TEST_ASSERT_EQUAL_MEMORY(MAC, out + 28, 6);    /* chaddr ecoado */
    /* xid ecoado (BE) */
    TEST_ASSERT_EQUAL_UINT8(0x11, out[4]);
    TEST_ASSERT_EQUAL_UINT8(0x44, out[7]);
    /* yiaddr = 192.168.1.100 en 16..19 */
    TEST_ASSERT_EQUAL_UINT8(192, out[16]);
    TEST_ASSERT_EQUAL_UINT8(100, out[19]);
    /* cookie */
    TEST_ASSERT_EQUAL_UINT8(0x63, out[236]);
    uint8_t l;
    const uint8_t *v = find_opt(out, n, 53, &l);
    TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(DHCP_OFFER, v[0]);
    v = find_opt(out, n, 1, &l);  TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(255, v[0]); /* mask .0 */
    v = find_opt(out, n, 3, &l);  TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(254, v[3]); /* gw .254 */
    v = find_opt(out, n, 6, &l);  TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(1, v[3]);   /* dns .1 */
    v = find_opt(out, n, 51, &l); TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(4, l);
    v = find_opt(out, n, 54, &l); TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(1, v[3]);
    /* termina en 255 */
    TEST_ASSERT_EQUAL_UINT8(255, out[n - 1]);
}

/* DW-07: NAK lleva solo 53 y 54 (sin 1/3/6/51) */
static void test_build_nak(void)
{
    uint8_t out[512];
    dhcp_reply_t r = {.msgtype = DHCP_NAK, .xid = 1, .mac = MAC, .server_id = 0xC0A80101u};
    size_t n = dhcp_build(&r, out, sizeof(out));
    TEST_ASSERT_TRUE(n >= 240);
    uint8_t l;
    const uint8_t *v = find_opt(out, n, 53, &l);
    TEST_ASSERT_NOT_NULL(v); TEST_ASSERT_EQUAL_UINT8(DHCP_NAK, v[0]);
    TEST_ASSERT_NOT_NULL(find_opt(out, n, 54, &l));
    TEST_ASSERT_NULL(find_opt(out, n, 1, &l));
    TEST_ASSERT_NULL(find_opt(out, n, 3, &l));
    TEST_ASSERT_NULL(find_opt(out, n, 51, &l));
}

/* DW-08: cap corto → 0 sin desbordar */
static void test_build_cap_corto(void)
{
    uint8_t out[250];
    dhcp_reply_t r = {.msgtype = DHCP_OFFER, .xid = 1, .mac = MAC, .yiaddr = 1,
                      .server_id = 1, .mask = 1, .gateway = 1, .dns = 1, .lease_time = 1};
    TEST_ASSERT_EQUAL_size_t(0, dhcp_build(&r, out, 240)); /* no cabe cabecera+opciones */
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_discover);
    RUN_TEST(test_parse_request);
    RUN_TEST(test_parse_hostname);
    RUN_TEST(test_parse_invalidos);
    RUN_TEST(test_parse_opcion_desbordada);
    RUN_TEST(test_parse_fuzz);
    RUN_TEST(test_build_offer);
    RUN_TEST(test_build_nak);
    RUN_TEST(test_build_cap_corto);
    return UNITY_END();
}
