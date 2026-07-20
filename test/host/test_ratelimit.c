/*
 * T015 — tests de ratelimit con reloj simulado (CB-42/43 unitarios, R6).
 */
#include "unity.h"

#include "ratelimit.h"

void setUp(void) {}
void tearDown(void) {}

static ratelimit_t rl;

static ip_addr16_t ipv4(uint8_t d)
{
    ip_addr16_t a = {.family = ESPHOLE_AF_V4, .bytes = {192, 168, 1, d}};
    return a;
}

static void test_rafaga_hasta_burst_y_luego_corta(void)
{
    ratelimit_init(&rl, 2, 5, 1000, 1000);
    ip_addr16_t a = ipv4(10);
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 1000));
    }
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &a, 1000));
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &a, 1001));
}

static void test_recarga_con_el_tiempo(void)
{
    ratelimit_init(&rl, 2, 5, 1000, 1000);
    ip_addr16_t a = ipv4(10);
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 1000));
    }
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &a, 1000));
    /* 1 s a 2 tokens/s ⇒ 2 admitidas más */
    TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 2000));
    TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 2000));
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &a, 2000));
}

static void test_recarga_no_excede_burst(void)
{
    ratelimit_init(&rl, 100, 5, 10000, 10000);
    ip_addr16_t a = ipv4(10);
    TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 1000));
    /* mucho tiempo después: el bucket vuelve a burst, no más */
    for (int i = 0; i < 5; i++) {
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 100000));
    }
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &a, 100000));
}

static void test_ips_aisladas_entre_si(void)
{
    ratelimit_init(&rl, 2, 3, 1000, 1000);
    ip_addr16_t a = ipv4(10);
    ip_addr16_t b = ipv4(20);
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 1000));
    }
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &a, 1000));
    /* el abuso de A no afecta a B (CB-42) */
    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &b, 1000));
    }
}

static void test_techo_global(void)
{
    ratelimit_init(&rl, 100, 100, 2, 4);
    /* IPs distintas con bucket propio holgado: el global corta en 4 */
    for (int i = 0; i < 4; i++) {
        ip_addr16_t a = ipv4((uint8_t)(30 + i));
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 1000));
    }
    ip_addr16_t z = ipv4(99);
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &z, 1000));   /* CB-43 */
    /* recuperación al pasar el tiempo */
    TEST_ASSERT_TRUE(ratelimit_check(&rl, &z, 2000));
}

static void test_desalojo_lru_de_la_tabla(void)
{
    ratelimit_init(&rl, 1, 1, 60000, 60000);
    /* llena la tabla: 64 IPs, cada una gasta su único token */
    for (int i = 0; i < RATELIMIT_TABLE; i++) {
        ip_addr16_t a = ipv4((uint8_t)i);
        TEST_ASSERT_TRUE(ratelimit_check(&rl, &a, 1000 + (uint32_t)i));
    }
    /* ip0 sigue en tabla y agotada */
    ip_addr16_t ip0 = ipv4(0);
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &ip0, 1100));
    /* IP 65: tabla llena ⇒ desaloja la LRU (ip1, usada en t=1001) */
    ip_addr16_t nueva = ipv4(200);
    TEST_ASSERT_TRUE(ratelimit_check(&rl, &nueva, 1101));
    /* ip1 fue desalojada: vuelve con bucket fresco (y desaloja a ip2, la
     * nueva LRU — el desalojo en cadena es la semántica esperada) */
    ip_addr16_t ip1 = ipv4(1);
    TEST_ASSERT_TRUE(ratelimit_check(&rl, &ip1, 1102));
    /* ip0 sigue en tabla (se refrescó en t=1100) y sigue agotada */
    TEST_ASSERT_FALSE(ratelimit_check(&rl, &ip0, 1103));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_rafaga_hasta_burst_y_luego_corta);
    RUN_TEST(test_recarga_con_el_tiempo);
    RUN_TEST(test_recarga_no_excede_burst);
    RUN_TEST(test_ips_aisladas_entre_si);
    RUN_TEST(test_techo_global);
    RUN_TEST(test_desalojo_lru_de_la_tabla);
    return UNITY_END();
}
