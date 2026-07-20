/*
 * T017 — tests de policy: subredes locales v4/v6 (CB-41 unitario) y tabla
 * de fail-open del camino rápido.
 */
#include <string.h>

#include "unity.h"

#include "policy.h"

void setUp(void) {}
void tearDown(void) {}

static ip_addr16_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    ip_addr16_t x = {.family = ESPHOLE_AF_V4, .bytes = {a, b, c, d}};
    return x;
}

static ip_addr16_t v6_pref(uint8_t b0, uint8_t b1)
{
    ip_addr16_t x = {.family = ESPHOLE_AF_V6, .bytes = {b0, b1}};
    x.bytes[15] = 1;
    return x;
}

static policy_t con_subred(ip_addr16_t base, uint8_t prefix)
{
    policy_t p;
    memset(&p, 0, sizeof(p));
    p.subnets[0].base = base;
    p.subnets[0].prefix_len = prefix;
    p.count = 1;
    return p;
}

static void test_v4_prefijo_24(void)
{
    policy_t p = con_subred(v4(192, 168, 1, 0), 24);
    ip_addr16_t dentro = v4(192, 168, 1, 55);
    ip_addr16_t fuera = v4(192, 168, 2, 55);
    ip_addr16_t wan = v4(8, 8, 8, 8);
    TEST_ASSERT_TRUE(policy_is_local(&p, &dentro));
    TEST_ASSERT_FALSE(policy_is_local(&p, &fuera));
    TEST_ASSERT_FALSE(policy_is_local(&p, &wan));
}

static void test_v4_prefijo_no_alineado_a_byte(void)
{
    policy_t p = con_subred(v4(192, 168, 1, 16), 28); /* .16 – .31 */
    ip_addr16_t in_bajo = v4(192, 168, 1, 16);
    ip_addr16_t in_alto = v4(192, 168, 1, 31);
    ip_addr16_t out_bajo = v4(192, 168, 1, 15);
    ip_addr16_t out_alto = v4(192, 168, 1, 32);
    TEST_ASSERT_TRUE(policy_is_local(&p, &in_bajo));
    TEST_ASSERT_TRUE(policy_is_local(&p, &in_alto));
    TEST_ASSERT_FALSE(policy_is_local(&p, &out_bajo));
    TEST_ASSERT_FALSE(policy_is_local(&p, &out_alto));
}

static void test_v6_prefijo_10(void)
{
    /* fe80::/10 cubre fe80..febf */
    policy_t p = con_subred(v6_pref(0xfe, 0x80), 10);
    ip_addr16_t in1 = v6_pref(0xfe, 0x80);
    ip_addr16_t in2 = v6_pref(0xfe, 0xbf);
    ip_addr16_t out1 = v6_pref(0xfe, 0xc0);
    ip_addr16_t out2 = v6_pref(0xfd, 0x00);
    TEST_ASSERT_TRUE(policy_is_local(&p, &in1));
    TEST_ASSERT_TRUE(policy_is_local(&p, &in2));
    TEST_ASSERT_FALSE(policy_is_local(&p, &out1));
    TEST_ASSERT_FALSE(policy_is_local(&p, &out2));
}

static void test_familias_no_se_mezclan(void)
{
    policy_t p = con_subred(v4(192, 168, 1, 0), 24);
    ip_addr16_t seis = v6_pref(0xc0, 0xa8); /* mismos bytes que 192.168 */
    TEST_ASSERT_FALSE(policy_is_local(&p, &seis));
}

static void test_varias_subredes(void)
{
    policy_t p = con_subred(v4(192, 168, 1, 0), 24);
    p.subnets[1].base = v6_pref(0xfd, 0x00);
    p.subnets[1].prefix_len = 8;
    p.count = 2;
    ip_addr16_t v6ula = v6_pref(0xfd, 0x12);
    TEST_ASSERT_TRUE(policy_is_local(&p, &v6ula));
}

static void test_sin_subredes_nada_es_local(void)
{
    policy_t p;
    memset(&p, 0, sizeof(p));
    ip_addr16_t a = v4(192, 168, 1, 1);
    TEST_ASSERT_FALSE(policy_is_local(&p, &a));
    TEST_ASSERT_FALSE(policy_is_local(NULL, &a));
    TEST_ASSERT_FALSE(policy_is_local(&p, NULL));
}

static void test_tabla_de_fail_open(void)
{
    /* solo lo malformado se descarta; todo lo demás degrada a reenvío (P-I) */
    TEST_ASSERT_EQUAL_INT(POLICY_DROP, policy_on_datapath_error(DNS_WIRE_MALFORMED));
    TEST_ASSERT_EQUAL_INT(POLICY_FORWARD, policy_on_datapath_error(DNS_WIRE_OK));
    TEST_ASSERT_EQUAL_INT(POLICY_FORWARD, policy_on_datapath_error(DNS_WIRE_UNSUPPORTED));
    TEST_ASSERT_EQUAL_INT(POLICY_FORWARD, policy_on_datapath_error(DNS_WIRE_BUFFER_SMALL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_v4_prefijo_24);
    RUN_TEST(test_v4_prefijo_no_alineado_a_byte);
    RUN_TEST(test_v6_prefijo_10);
    RUN_TEST(test_familias_no_se_mezclan);
    RUN_TEST(test_varias_subredes);
    RUN_TEST(test_sin_subredes_nada_es_local);
    RUN_TEST(test_tabla_de_fail_open);
    return UNITY_END();
}
