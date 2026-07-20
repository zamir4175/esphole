/*
 * T002: verifica que el arnés compila, linka Unity y ve los headers de los
 * componentes. Incluir esphole_types.h aquí prueba que el header común (T003)
 * compila en host sin ESP-IDF.
 */
#include "unity.h"

#include "esphole_types.h"

void setUp(void) {}
void tearDown(void) {}

static void test_harness_and_common_types(void)
{
    ip_addr16_t a = {0};
    a.family = ESPHOLE_AF_V4;
    TEST_ASSERT_EQUAL_UINT(16, sizeof(a.bytes));
    TEST_ASSERT_EQUAL_INT(253, ESPHOLE_DOMAIN_MAX);

    dns_query_t q = {0};
    q.qtype = DNS_TYPE_AAAA;
    TEST_ASSERT_EQUAL_UINT16(28, q.qtype);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_harness_and_common_types);
    return UNITY_END();
}
