/*
 * Tests host de dhcp_lease (spec 006, contrato DL-01..10). Reloj inyectado.
 */
#include <string.h>

#include "unity.h"

#include "dhcp_lease.h"

void setUp(void) {}
void tearDown(void) {}

#define IP100 0xC0A80164u /* 192.168.1.100 */
#define IP101 0xC0A80165u
#define IP102 0xC0A80166u
#define OUTSIDE 0xC0A801C8u /* 192.168.1.200, fuera del pool */

static const uint8_t M1[6] = {0, 0, 0, 0, 0, 1};
static const uint8_t M2[6] = {0, 0, 0, 0, 0, 2};
static const uint8_t M3[6] = {0, 0, 0, 0, 0, 3};
static const uint8_t M4[6] = {0, 0, 0, 0, 0, 4};

static dhcp_leases_t t;

/* pool de 3 IPs: .100 .101 .102 */
static dhcp_pool_t pool(void)
{
    dhcp_pool_t p = {.start = IP100, .end = IP102, .mask = 0xFFFFFF00u,
                     .gateway = 0xC0A801FEu, .dns = 0xC0A80101u,
                     .own_ip = 0xC0A80101u, .lease_time = 3600};
    return p;
}

/* DL-01: pool vacío → primera libre */
static void test_offer_primera_libre(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    TEST_ASSERT_EQUAL_HEX32(IP100, dhcp_lease_offer(&t, &p, M1, 0, 1000));
}

/* DL-02: honrar la IP pedida si está libre */
static void test_offer_honra_pedida(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    TEST_ASSERT_EQUAL_HEX32(IP102, dhcp_lease_offer(&t, &p, M1, IP102, 1000));
    /* pedir una fuera del pool → cae a la primera libre */
    TEST_ASSERT_EQUAL_HEX32(IP100, dhcp_lease_offer(&t, &p, M2, OUTSIDE, 1000));
}

/* DL-03: el mismo MAC recupera su IP */
static void test_offer_mismo_mac(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    uint32_t a = dhcp_lease_offer(&t, &p, M1, 0, 1000);
    uint32_t b = dhcp_lease_offer(&t, &p, M1, 0, 1001);
    TEST_ASSERT_EQUAL_HEX32(a, b);
}

/* DL-04: commit tras offer → BOUND/ACK */
static void test_commit_ack(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    dhcp_lease_offer(&t, &p, M1, 0, 1000);
    TEST_ASSERT_TRUE(dhcp_lease_commit(&t, &p, M1, IP100, 1000, "pc1"));
}

/* DL-05: commit inválido → NAK */
static void test_commit_nak(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    /* IP fuera del pool */
    TEST_ASSERT_FALSE(dhcp_lease_commit(&t, &p, M1, OUTSIDE, 1000, NULL));
    /* IP de otro MAC ya confirmada */
    dhcp_lease_offer(&t, &p, M1, IP100, 1000);
    TEST_ASSERT_TRUE(dhcp_lease_commit(&t, &p, M1, IP100, 1000, NULL));
    TEST_ASSERT_FALSE(dhcp_lease_commit(&t, &p, M2, IP100, 1000, NULL));
}

/* DL-06: pool lleno → 0 */
static void test_pool_lleno(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    TEST_ASSERT_NOT_EQUAL(0, dhcp_lease_offer(&t, &p, M1, 0, 1000));
    TEST_ASSERT_NOT_EQUAL(0, dhcp_lease_offer(&t, &p, M2, 0, 1000));
    TEST_ASSERT_NOT_EQUAL(0, dhcp_lease_offer(&t, &p, M3, 0, 1000));
    TEST_ASSERT_EQUAL_HEX32(0, dhcp_lease_offer(&t, &p, M4, 0, 1000)); /* lleno */
}

/* DL-07: expiración libera la IP */
static void test_expiracion(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    dhcp_lease_offer(&t, &p, M1, IP100, 1000);
    TEST_ASSERT_TRUE(dhcp_lease_commit(&t, &p, M1, IP100, 1000, NULL)); /* expira 1000+3600 */
    dhcp_lease_expire(&t, 1000 + 3600 + 1);
    /* .100 vuelve a estar libre para otro MAC */
    TEST_ASSERT_EQUAL_HEX32(IP100, dhcp_lease_offer(&t, &p, M4, IP100, 5000));
}

/* DL-08: release libera la IP */
static void test_release(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    dhcp_lease_offer(&t, &p, M1, IP100, 1000);
    dhcp_lease_commit(&t, &p, M1, IP100, 1000, NULL);
    dhcp_lease_release(&t, M1, IP100);
    TEST_ASSERT_EQUAL_HEX32(IP100, dhcp_lease_offer(&t, &p, M4, IP100, 1001));
}

/* DL-09: decline marca BAD (no se vuelve a ofrecer) */
static void test_decline(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    dhcp_lease_decline(&t, IP100);
    /* ni pidiéndola ni por barrido se ofrece .100 */
    uint32_t a = dhcp_lease_offer(&t, &p, M1, IP100, 1000);
    TEST_ASSERT_NOT_EQUAL(IP100, a);
    uint32_t b = dhcp_lease_offer(&t, &p, M2, 0, 1000);
    TEST_ASSERT_NOT_EQUAL(IP100, b);
}

/* DL-10: dos MAC distintas → IPs distintas (offer reserva) */
static void test_dos_mac_distintas(void)
{
    dhcp_leases_init(&t);
    dhcp_pool_t p = pool();
    uint32_t a = dhcp_lease_offer(&t, &p, M1, 0, 1000);
    uint32_t b = dhcp_lease_offer(&t, &p, M2, 0, 1000);
    TEST_ASSERT_NOT_EQUAL(0, a);
    TEST_ASSERT_NOT_EQUAL(0, b);
    TEST_ASSERT_NOT_EQUAL(a, b);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_offer_primera_libre);
    RUN_TEST(test_offer_honra_pedida);
    RUN_TEST(test_offer_mismo_mac);
    RUN_TEST(test_commit_ack);
    RUN_TEST(test_commit_nak);
    RUN_TEST(test_pool_lleno);
    RUN_TEST(test_expiracion);
    RUN_TEST(test_release);
    RUN_TEST(test_decline);
    RUN_TEST(test_dos_mac_distintas);
    return UNITY_END();
}
