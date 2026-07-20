/*
 * T013 — tests de cache con reloj simulado (FR-005, FR-016, C4).
 */
#include <string.h>

#include "unity.h"

#include "cache.h"
#include "dns_wire.h"
#include "wire_helpers.h"

void setUp(void) {}
void tearDown(void) {}

static uint8_t mem[128 * 1024];
static cache_t c;
static uint8_t out[ESPHOLE_RESP_MAX];

/* consulta parseada para 'name' */
static dns_query_t consulta_q(const char *name, uint16_t qtype, uint16_t id)
{
    /* buffers rotatorios: q.raw debe sobrevivir mientras el test use la
     * consulta, aunque se creen varias consultas en el mismo test */
    static pkt_t bufs[16];
    static unsigned bi;
    pkt_t *p = &bufs[bi++ % 16];
    *p = consulta(name, qtype);
    p->b[0] = (uint8_t)(id >> 8);
    p->b[1] = (uint8_t)(id & 0xFF);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p->b, p->len, &q));
    return q;
}

/* respuesta A con un answer y TTL dado */
static pkt_t respuesta_a(const char *name, uint32_t ttl)
{
    static const uint8_t ip[4] = {93, 184, 216, 34};
    pkt_t p = {.len = 0};
    pheader(&p, 0x9999, 0x8180, 1, 1, 0, 0);
    pname(&p, name);
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    precord(&p, DNS_TYPE_A, ttl, ip, 4);
    return p;
}

static void init4(void)
{
    TEST_ASSERT_TRUE(cache_mem_size(4) <= sizeof(mem));
    cache_init(&c, mem, 4, 3600);
}

/* --- básicos --- */

static void test_miss_en_cache_vacia(void)
{
    init4();
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 0x1111);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 1000, out, sizeof(out)));
}

static void test_hit_reescribe_id_y_decrementa_ttl(void)
{
    init4();
    dns_query_t q1 = consulta_q("example.com", DNS_TYPE_A, 0x1111);
    pkt_t r = respuesta_a("example.com", 100);
    cache_put(&c, &q1, r.b, r.len, 100, 1000);

    dns_query_t q2 = consulta_q("example.com", DNS_TYPE_A, 0x2222);
    size_t n = cache_get(&c, &q2, 1030, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(r.len, n);
    TEST_ASSERT_EQUAL_HEX16(0x2222, rd16at(out, 0)); /* ID del segundo cliente */
    uint32_t ttl = 0;
    TEST_ASSERT_TRUE(dns_wire_min_ttl(out, n, &ttl));
    TEST_ASSERT_EQUAL_UINT32(70, ttl); /* 100 - 30 transcurridos */
}

static void test_hit_ecoa_pregunta_con_casing_del_cliente(void)
{
    init4();
    dns_query_t q1 = consulta_q("example.com", DNS_TYPE_A, 0x1111);
    pkt_t r = respuesta_a("example.com", 100);
    cache_put(&c, &q1, r.b, r.len, 100, 1000);

    dns_query_t q2 = consulta_q("ExAmPlE.cOm", DNS_TYPE_A, 0x2222);
    size_t n = cache_get(&c, &q2, 1001, out, sizeof(out));
    TEST_ASSERT_TRUE(n > 0);
    /* la sección de pregunta es byte a byte la del cliente actual (dns0x20) */
    TEST_ASSERT_EQUAL_MEMORY(q2.raw + 12, out + 12, q2.question_end - 12);
}

static void test_clave_distingue_tipo(void)
{
    init4();
    dns_query_t qa = consulta_q("example.com", DNS_TYPE_A, 1);
    pkt_t r = respuesta_a("example.com", 100);
    cache_put(&c, &qa, r.b, r.len, 100, 1000);

    dns_query_t q4 = consulta_q("example.com", DNS_TYPE_AAAA, 2);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q4, 1001, out, sizeof(out)));
}

/* --- expiración (FR-005 / CB-51) --- */

static void test_jamas_sirve_expirado(void)
{
    init4();
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 1);
    pkt_t r = respuesta_a("example.com", 100);
    cache_put(&c, &q, r.b, r.len, 100, 1000);

    TEST_ASSERT_TRUE(cache_get(&c, &q, 1099, out, sizeof(out)) > 0);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 1100, out, sizeof(out)));
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 5000, out, sizeof(out)));
}

/* --- políticas de inserción (FR-016 / CB-52/53/57) --- */

static void test_ttl_cero_no_se_cachea(void)
{
    init4();
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 1);
    pkt_t r = respuesta_a("example.com", 0);
    cache_put(&c, &q, r.b, r.len, 0, 1000);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 1000, out, sizeof(out)));
}

static void test_ttl_se_recorta_al_tope(void)
{
    init4(); /* ttl_cap = 3600 */
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 1);
    pkt_t r = respuesta_a("example.com", 10000);
    cache_put(&c, &q, r.b, r.len, 10000, 1000);
    TEST_ASSERT_TRUE(cache_get(&c, &q, 1000 + 3599, out, sizeof(out)) > 0);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 1000 + 3600, out, sizeof(out)));
}

static void test_respuesta_grande_no_se_cachea(void)
{
    init4();
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 1);
    static uint8_t grande[ESPHOLE_RESP_MAX + 88];
    pkt_t r = respuesta_a("example.com", 100);
    memcpy(grande, r.b, r.len);
    cache_put(&c, &q, grande, sizeof(grande), 100, 1000);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 1001, out, sizeof(out)));
}

static void test_servfail_no_se_cachea(void)
{
    init4();
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 1);
    pkt_t r = respuesta_a("example.com", 100);
    r.b[3] = (uint8_t)((r.b[3] & 0xF0) | DNS_RCODE_SERVFAIL);
    cache_put(&c, &q, r.b, r.len, 100, 1000);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &q, 1001, out, sizeof(out)));
}

static void test_nxdomain_si_se_cachea(void)
{
    init4();
    dns_query_t q = consulta_q("nx.example.com", DNS_TYPE_A, 1);
    uint8_t soa_rdata[22] = {0};
    pkt_t r = {.len = 0};
    pheader(&r, 0x9999, 0x8183 /* NXDOMAIN */, 1, 0, 1, 0);
    pname(&r, "nx.example.com");
    p16(&r, DNS_TYPE_A);
    p16(&r, DNS_CLASS_IN);
    precord(&r, DNS_TYPE_SOA, 900, soa_rdata, sizeof(soa_rdata));
    cache_put(&c, &q, r.b, r.len, 900, 1000);
    size_t n = cache_get(&c, &q, 1001, out, sizeof(out));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_UINT8(DNS_RCODE_NXDOMAIN, dns_wire_rcode(out, n));
}

static void test_reemplaza_clave_existente(void)
{
    init4();
    dns_query_t q = consulta_q("example.com", DNS_TYPE_A, 1);
    pkt_t r1 = respuesta_a("example.com", 50);
    cache_put(&c, &q, r1.b, r1.len, 50, 1000);
    pkt_t r2 = respuesta_a("example.com", 300);
    cache_put(&c, &q, r2.b, r2.len, 300, 1000);

    uint32_t ttl = 0;
    size_t n = cache_get(&c, &q, 1000, out, sizeof(out));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_TRUE(dns_wire_min_ttl(out, n, &ttl));
    TEST_ASSERT_EQUAL_UINT32(300, ttl);
}

/* --- desalojo (FR-016 / CB-54) --- */

static const char *NOMBRES[] = {"a.test", "b.test", "c.test", "d.test", "e.test"};

static void llena4(uint32_t now)
{
    for (int i = 0; i < 4; i++) {
        dns_query_t q = consulta_q(NOMBRES[i], DNS_TYPE_A, (uint16_t)i);
        pkt_t r = respuesta_a(NOMBRES[i], 500);
        cache_put(&c, &q, r.b, r.len, 500, now);
    }
}

static void test_desaloja_lru_cuando_esta_llena(void)
{
    init4();
    llena4(1000);
    /* refresca a,b,c: 'd' queda como LRU */
    for (int i = 0; i < 3; i++) {
        dns_query_t q = consulta_q(NOMBRES[i], DNS_TYPE_A, 9);
        TEST_ASSERT_TRUE(cache_get(&c, &q, 1010, out, sizeof(out)) > 0);
    }
    dns_query_t q5 = consulta_q(NOMBRES[4], DNS_TYPE_A, 5);
    pkt_t r5 = respuesta_a(NOMBRES[4], 500);
    cache_put(&c, &q5, r5.b, r5.len, 500, 1020);

    TEST_ASSERT_EQUAL_UINT32(1, cache_evictions(&c));
    dns_query_t qd = consulta_q("d.test", DNS_TYPE_A, 6);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &qd, 1021, out, sizeof(out)));
    dns_query_t qa = consulta_q("a.test", DNS_TYPE_A, 7);
    TEST_ASSERT_TRUE(cache_get(&c, &qa, 1021, out, sizeof(out)) > 0);
    dns_query_t qe = consulta_q("e.test", DNS_TYPE_A, 8);
    TEST_ASSERT_TRUE(cache_get(&c, &qe, 1021, out, sizeof(out)) > 0);
}

static void test_desaloja_expirada_antes_que_lru(void)
{
    init4();
    /* 'a' expira pronto; el resto dura */
    dns_query_t qa = consulta_q("a.test", DNS_TYPE_A, 0);
    pkt_t ra = respuesta_a("a.test", 5);
    cache_put(&c, &qa, ra.b, ra.len, 5, 1000);
    for (int i = 1; i < 4; i++) {
        dns_query_t q = consulta_q(NOMBRES[i], DNS_TYPE_A, (uint16_t)i);
        pkt_t r = respuesta_a(NOMBRES[i], 500);
        cache_put(&c, &q, r.b, r.len, 500, 1001 + (uint32_t)i);
    }
    /* 'a' es ahora la MÁS recientemente usada... y está expirada */
    TEST_ASSERT_TRUE(cache_get(&c, &qa, 1004, out, sizeof(out)) > 0);

    dns_query_t q5 = consulta_q(NOMBRES[4], DNS_TYPE_A, 5);
    pkt_t r5 = respuesta_a(NOMBRES[4], 500);
    cache_put(&c, &q5, r5.b, r5.len, 500, 1100); /* 'a' ya expiró */

    /* debe desalojar la expirada 'a', no la cola LRU 'b' */
    dns_query_t qb = consulta_q("b.test", DNS_TYPE_A, 6);
    TEST_ASSERT_TRUE(cache_get(&c, &qb, 1101, out, sizeof(out)) > 0);
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &qa, 1101, out, sizeof(out)));
    dns_query_t qe = consulta_q("e.test", DNS_TYPE_A, 7);
    TEST_ASSERT_TRUE(cache_get(&c, &qe, 1101, out, sizeof(out)) > 0);
}

/* --- accesorios de la spec 003: ocupación y vaciado --- */

static void test_count_y_clear(void)
{
    init4();
    TEST_ASSERT_EQUAL_UINT16(0, cache_count(&c));
    dns_query_t qa = consulta_q("a.test", DNS_TYPE_A, 1);
    pkt_t ra = respuesta_a("a.test", 500);
    cache_put(&c, &qa, ra.b, ra.len, 500, 1000);
    dns_query_t qb = consulta_q("b.test", DNS_TYPE_A, 2);
    pkt_t rb = respuesta_a("b.test", 500);
    cache_put(&c, &qb, rb.b, rb.len, 500, 1000);
    TEST_ASSERT_EQUAL_UINT16(2, cache_count(&c));

    cache_clear(&c);
    TEST_ASSERT_EQUAL_UINT16(0, cache_count(&c));
    /* tras vaciar no sirve nada, pero sigue usable: se puede repoblar */
    uint8_t out[ESPHOLE_RESP_MAX];
    TEST_ASSERT_EQUAL_size_t(0, cache_get(&c, &qa, 1001, out, sizeof(out)));
    cache_put(&c, &qa, ra.b, ra.len, 500, 1002);
    TEST_ASSERT_EQUAL_UINT16(1, cache_count(&c));
    TEST_ASSERT_TRUE(cache_get(&c, &qa, 1003, out, sizeof(out)) > 0);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_miss_en_cache_vacia);
    RUN_TEST(test_hit_reescribe_id_y_decrementa_ttl);
    RUN_TEST(test_hit_ecoa_pregunta_con_casing_del_cliente);
    RUN_TEST(test_clave_distingue_tipo);
    RUN_TEST(test_jamas_sirve_expirado);
    RUN_TEST(test_ttl_cero_no_se_cachea);
    RUN_TEST(test_ttl_se_recorta_al_tope);
    RUN_TEST(test_respuesta_grande_no_se_cachea);
    RUN_TEST(test_servfail_no_se_cachea);
    RUN_TEST(test_nxdomain_si_se_cachea);
    RUN_TEST(test_reemplaza_clave_existente);
    RUN_TEST(test_desaloja_lru_cuando_esta_llena);
    RUN_TEST(test_desaloja_expirada_antes_que_lru);
    RUN_TEST(test_count_y_clear);
    return UNITY_END();
}
