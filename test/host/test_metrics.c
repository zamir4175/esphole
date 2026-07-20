/*
 * T022 — tests de metrics (CB-61 unitario: identidad contable y buckets).
 */
#include "unity.h"

#include "metrics.h"

void setUp(void) { metrics_init(); }
void tearDown(void) {}

static void test_arranca_a_cero_e_incrementa(void)
{
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    for (int i = 0; i < MET__COUNT; i++) {
        TEST_ASSERT_EQUAL_UINT32(0, s.contador[i]);
    }
    metrics_inc(MET_TOTAL);
    metrics_inc(MET_TOTAL);
    metrics_inc(MET_BLOQUEADAS);
    metrics_snapshot(&s);
    TEST_ASSERT_EQUAL_UINT32(2, s.contador[MET_TOTAL]);
    TEST_ASSERT_EQUAL_UINT32(1, s.contador[MET_BLOQUEADAS]);
    TEST_ASSERT_EQUAL_UINT32(0, s.contador[MET_CACHE_HITS]);
}

static void test_fallos_por_upstream(void)
{
    metrics_upstream_fallo(0);
    metrics_upstream_fallo(3);
    metrics_upstream_fallo(3);
    metrics_upstream_fallo(200); /* fuera de rango: se ignora sin reventar */
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    TEST_ASSERT_EQUAL_UINT32(1, s.upstream_fallos[0]);
    TEST_ASSERT_EQUAL_UINT32(0, s.upstream_fallos[1]);
    TEST_ASSERT_EQUAL_UINT32(2, s.upstream_fallos[3]);
}

static void test_histograma_de_latencia(void)
{
    /* fronteras exactas de los buckets <1, <10, <50, <100, <500, ≥500 */
    metrics_latencia_ms(0);    /* <1 */
    metrics_latencia_ms(1);    /* <10 */
    metrics_latencia_ms(9);    /* <10 */
    metrics_latencia_ms(10);   /* <50 */
    metrics_latencia_ms(49);   /* <50 */
    metrics_latencia_ms(99);   /* <100 */
    metrics_latencia_ms(100);  /* <500 */
    metrics_latencia_ms(499);  /* <500 */
    metrics_latencia_ms(500);  /* ≥500 */
    metrics_latencia_ms(60000);/* ≥500 */
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    TEST_ASSERT_EQUAL_UINT32(1, s.latencia_hist[0]);
    TEST_ASSERT_EQUAL_UINT32(2, s.latencia_hist[1]);
    TEST_ASSERT_EQUAL_UINT32(2, s.latencia_hist[2]);
    TEST_ASSERT_EQUAL_UINT32(1, s.latencia_hist[3]);
    TEST_ASSERT_EQUAL_UINT32(2, s.latencia_hist[4]);
    TEST_ASSERT_EQUAL_UINT32(2, s.latencia_hist[5]);
}

static void test_latencia_inline_conserva_el_maximo(void)
{
    metrics_latencia_inline_us(40);
    metrics_latencia_inline_us(90);
    metrics_latencia_inline_us(60);
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    TEST_ASSERT_EQUAL_UINT32(90, s.latencia_inline_max_us);
}

static void test_init_resetea(void)
{
    metrics_inc(MET_TOTAL);
    metrics_latencia_inline_us(99);
    metrics_init();
    metrics_snapshot_t s;
    metrics_snapshot(&s);
    TEST_ASSERT_EQUAL_UINT32(0, s.contador[MET_TOTAL]);
    TEST_ASSERT_EQUAL_UINT32(0, s.latencia_inline_max_us);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_arranca_a_cero_e_incrementa);
    RUN_TEST(test_fallos_por_upstream);
    RUN_TEST(test_histograma_de_latencia);
    RUN_TEST(test_latencia_inline_conserva_el_maximo);
    RUN_TEST(test_init_resetea);
    return UNITY_END();
}
