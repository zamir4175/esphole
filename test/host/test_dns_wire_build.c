/*
 * T008 — tests de constructores y mutadores de dns_wire
 * (CB-10/11/15, CB-30/31 a nivel unitario; dns0x20 en el eco de la pregunta).
 */
#include <string.h>

#include "unity.h"

#include "dns_wire.h"
#include "wire_helpers.h"

void setUp(void) {}
void tearDown(void) {}

static uint8_t out[512];

/* parsea una consulta construida y exige OK */
static dns_query_t parseada(const pkt_t *p)
{
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p->b, p->len, &q));
    return q;
}

/* --- respuesta de agujero negro --- */

static void test_bloqueo_a(void)
{
    pkt_t p = consulta("Ads.EXample.com", DNS_TYPE_A); /* casing mixto: dns0x20 */
    dns_query_t q = parseada(&p);

    size_t n = dns_wire_build_block_response(&q, 30, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(q.question_end + 16u, n);

    TEST_ASSERT_EQUAL_HEX16(0x1234, rd16at(out, 0));         /* ID eco */
    TEST_ASSERT_EQUAL_HEX8(0x85, out[2]); /* QR=1 AA=1 RD=1 */
    TEST_ASSERT_EQUAL_HEX8(0x80, out[3]); /* RA=1 RCODE=0 */
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(out, 4));             /* QDCOUNT */
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(out, 6));             /* ANCOUNT */
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(out, 8));              /* NSCOUNT */
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(out, 10));             /* ARCOUNT */

    /* la pregunta se ecoa byte a byte con su casing original */
    TEST_ASSERT_EQUAL_MEMORY(p.b + 12, out + 12, q.question_end - 12);

    size_t a = q.question_end;
    TEST_ASSERT_EQUAL_HEX16(0xC00C, rd16at(out, a));          /* puntero al nombre */
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_A, rd16at(out, a + 2));
    TEST_ASSERT_EQUAL_UINT16(DNS_CLASS_IN, rd16at(out, a + 4));
    TEST_ASSERT_EQUAL_UINT32(30, rd32at(out, a + 6));         /* TTL */
    TEST_ASSERT_EQUAL_UINT16(4, rd16at(out, a + 10));         /* RDLENGTH */
    TEST_ASSERT_EQUAL_UINT32(0, rd32at(out, a + 12));         /* 0.0.0.0 */
}

static void test_bloqueo_aaaa(void)
{
    pkt_t p = consulta("ads.example.com", DNS_TYPE_AAAA);
    dns_query_t q = parseada(&p);

    size_t n = dns_wire_build_block_response(&q, 30, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(q.question_end + 28u, n);

    size_t a = q.question_end;
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_AAAA, rd16at(out, a + 2));
    TEST_ASSERT_EQUAL_UINT16(16, rd16at(out, a + 10));
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT_EQUAL_HEX8(0, out[a + 12 + i]); /* :: */
    }
}

static void test_bloqueo_otro_tipo_sin_datos(void)
{
    /* dominio bloqueado consultado por MX: NOERROR con 0 respuestas */
    pkt_t p = consulta("ads.example.com", DNS_TYPE_MX);
    dns_query_t q = parseada(&p);

    size_t n = dns_wire_build_block_response(&q, 30, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t((size_t)q.question_end, n);
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(out, 6)); /* ANCOUNT */
    TEST_ASSERT_EQUAL_HEX8(0x80, out[3]);        /* RCODE=0 */
}

static void test_bloqueo_con_edns_incluye_opt(void)
{
    pkt_t p = consulta("ads.example.com", DNS_TYPE_A);
    p.b[11] = 1;
    popt(&p, 4096);
    dns_query_t q = parseada(&p);

    size_t n = dns_wire_build_block_response(&q, 30, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(q.question_end + 16u + 11u, n);
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(out, 10)); /* ARCOUNT */

    size_t o = q.question_end + 16u; /* OPT tras la respuesta */
    TEST_ASSERT_EQUAL_HEX8(0, out[o]);            /* raíz */
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_OPT, rd16at(out, o + 1));
    TEST_ASSERT_EQUAL_UINT16(DNS_WIRE_OUR_EDNS_PAYLOAD, rd16at(out, o + 3));
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(out, o + 9)); /* RDLENGTH */
}

static void test_bloqueo_buffer_insuficiente(void)
{
    pkt_t p = consulta("ads.example.com", DNS_TYPE_A);
    dns_query_t q = parseada(&p);
    TEST_ASSERT_EQUAL_size_t(0, dns_wire_build_block_response(&q, 30, out, 20));
}

/* --- respuesta de error --- */

static void test_respuesta_servfail(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    dns_query_t q = parseada(&p);

    size_t n = dns_wire_build_rcode_response(&q, DNS_RCODE_SERVFAIL, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t((size_t)q.question_end, n);
    TEST_ASSERT_TRUE(out[2] & 0x80);                      /* QR=1 */
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(out, 6));          /* sin respuestas */
    TEST_ASSERT_EQUAL_UINT8(DNS_RCODE_SERVFAIL, dns_wire_rcode(out, n));
}

/* --- mutadores --- */

static void test_rewrite_id(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    dns_wire_rewrite_id(p.b, p.len, 0xBEEF);
    TEST_ASSERT_EQUAL_HEX16(0xBEEF, rd16at(p.b, 0));
    dns_wire_rewrite_id(p.b, 1, 0x0000); /* corto: no toca ni revienta */
    TEST_ASSERT_EQUAL_HEX16(0xBEEF, rd16at(p.b, 0));
}

/* respuesta sintética: pregunta + 2 answers (TTL 300 y 60) + OPT */
static pkt_t respuesta_dos_answers(void)
{
    static const uint8_t ip[4] = {93, 184, 216, 34};
    pkt_t p = {.len = 0};
    pheader(&p, 0x1234, 0x8180, 1, 2, 0, 1);
    pname(&p, "example.com");
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    precord(&p, DNS_TYPE_A, 300, ip, 4);
    precord(&p, DNS_TYPE_A, 60, ip, 4);
    popt(&p, 1232);
    return p;
}

static void test_min_ttl_de_answers(void)
{
    pkt_t p = respuesta_dos_answers();
    uint32_t ttl = 0;
    TEST_ASSERT_TRUE(dns_wire_min_ttl(p.b, p.len, &ttl));
    TEST_ASSERT_EQUAL_UINT32(60, ttl);
}

static void test_min_ttl_negativa_usa_soa(void)
{
    /* NXDOMAIN sin answers, SOA en authority con TTL 900 */
    uint8_t soa_rdata[22] = {0}; /* mname+rname raíz + 20 bytes de contadores */
    pkt_t p = {.len = 0};
    pheader(&p, 1, 0x8183, 1, 0, 1, 0);
    pname(&p, "nx.example.com");
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    precord(&p, DNS_TYPE_SOA, 900, soa_rdata, sizeof(soa_rdata));
    uint32_t ttl = 0;
    TEST_ASSERT_TRUE(dns_wire_min_ttl(p.b, p.len, &ttl));
    TEST_ASSERT_EQUAL_UINT32(900, ttl);
}

static void test_min_ttl_sin_registros(void)
{
    pkt_t p = {.len = 0};
    pheader(&p, 1, 0x8180, 1, 0, 0, 0);
    pname(&p, "example.com");
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    uint32_t ttl = 0;
    TEST_ASSERT_FALSE(dns_wire_min_ttl(p.b, p.len, &ttl));
}

static void test_decrement_ttls_respeta_opt(void)
{
    pkt_t p = respuesta_dos_answers();
    /* localiza el OPT (últimos 11 bytes) y dale "TTL" con flags */
    size_t opt_ttl_off = p.len - 6; /* raíz(1)+type(2)+class(2) ... ttl en -6 */
    p.b[opt_ttl_off] = 0x00;
    p.b[opt_ttl_off + 1] = 0x00;
    p.b[opt_ttl_off + 2] = 0x80; /* flag DO */
    p.b[opt_ttl_off + 3] = 0x00;

    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_decrement_ttls(p.b, p.len, 50));

    uint32_t ttl = 0;
    TEST_ASSERT_TRUE(dns_wire_min_ttl(p.b, p.len, &ttl));
    TEST_ASSERT_EQUAL_UINT32(10, ttl); /* 60-50 */
    TEST_ASSERT_EQUAL_HEX8(0x80, p.b[opt_ttl_off + 2]); /* OPT intacto */
}

static void test_decrement_ttls_satura_en_cero(void)
{
    pkt_t p = respuesta_dos_answers();
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_decrement_ttls(p.b, p.len, 1000));
    uint32_t ttl = 99;
    TEST_ASSERT_TRUE(dns_wire_min_ttl(p.b, p.len, &ttl));
    TEST_ASSERT_EQUAL_UINT32(0, ttl);
}

/* --- truncado (CB-31) --- */

static void test_truncate_deja_pregunta_y_opt(void)
{
    pkt_t p = respuesta_dos_answers();
    size_t qend = 12 + 13 + 4;

    size_t n = dns_wire_truncate(p.b, p.len, 512);
    TEST_ASSERT_EQUAL_size_t(qend + 11u, n);
    TEST_ASSERT_TRUE(p.b[2] & 0x02);              /* TC=1 */
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(p.b, 4));  /* QDCOUNT */
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(p.b, 6));  /* ANCOUNT */
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(p.b, 8));
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(p.b, 10)); /* OPT conservado */
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_OPT, rd16at(p.b, qend + 1));
}

static void test_truncate_sin_opt(void)
{
    static const uint8_t ip[4] = {1, 2, 3, 4};
    pkt_t p = {.len = 0};
    pheader(&p, 1, 0x8180, 1, 1, 0, 0);
    pname(&p, "example.com");
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    precord(&p, DNS_TYPE_A, 300, ip, 4);
    size_t qend = 12 + 13 + 4;

    size_t n = dns_wire_truncate(p.b, p.len, 512);
    TEST_ASSERT_EQUAL_size_t(qend, n);
    TEST_ASSERT_TRUE(p.b[2] & 0x02);
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(p.b, 10));
}

/* --- respuesta A a IP fija (DNS cautivo del aprovisionamiento, PB-H5) --- */

static void test_a_response_ip_fija(void)
{
    pkt_t p = consulta("Cualquier.Cosa.com", DNS_TYPE_A); /* casing mixto */
    dns_query_t q = parseada(&p);
    const uint8_t ip[4] = {192, 168, 4, 1};

    size_t n = dns_wire_build_a_response(&q, ip, 60, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(q.question_end + 16u, n);

    TEST_ASSERT_EQUAL_HEX16(0x1234, rd16at(out, 0)); /* ID eco */
    TEST_ASSERT_EQUAL_HEX8(0x85, out[2]);            /* QR=1 AA=1 RD=1 */
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(out, 6));     /* ANCOUNT */
    /* pregunta ecoada byte a byte (dns0x20) */
    TEST_ASSERT_EQUAL_MEMORY(p.b + 12, out + 12, q.question_end - 12);

    size_t a = q.question_end;
    TEST_ASSERT_EQUAL_HEX16(0xC00C, rd16at(out, a));
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_A, rd16at(out, a + 2));
    TEST_ASSERT_EQUAL_UINT16(DNS_CLASS_IN, rd16at(out, a + 4));
    TEST_ASSERT_EQUAL_UINT32(60, rd32at(out, a + 6));
    TEST_ASSERT_EQUAL_UINT16(4, rd16at(out, a + 10));
    TEST_ASSERT_EQUAL_UINT8(192, out[a + 12]);
    TEST_ASSERT_EQUAL_UINT8(168, out[a + 13]);
    TEST_ASSERT_EQUAL_UINT8(4, out[a + 14]);
    TEST_ASSERT_EQUAL_UINT8(1, out[a + 15]);
}

static void test_a_response_tipo_no_a_sin_datos(void)
{
    pkt_t p = consulta("cualquier.cosa.com", DNS_TYPE_AAAA);
    dns_query_t q = parseada(&p);
    const uint8_t ip[4] = {192, 168, 4, 1};

    size_t n = dns_wire_build_a_response(&q, ip, 60, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t((size_t)q.question_end, n);
    TEST_ASSERT_EQUAL_UINT16(0, rd16at(out, 6)); /* ANCOUNT=0 */
}

static void test_a_response_con_edns(void)
{
    pkt_t p = consulta("cualquier.cosa.com", DNS_TYPE_A);
    p.b[11] = 1;
    popt(&p, 1232);
    dns_query_t q = parseada(&p);
    const uint8_t ip[4] = {10, 0, 0, 1};

    size_t n = dns_wire_build_a_response(&q, ip, 60, out, sizeof(out));
    TEST_ASSERT_EQUAL_size_t(q.question_end + 16u + 11u, n);
    TEST_ASSERT_EQUAL_UINT16(1, rd16at(out, 10)); /* ARCOUNT: OPT propio */
}

static void test_a_response_buffer_insuficiente(void)
{
    pkt_t p = consulta("cualquier.cosa.com", DNS_TYPE_A);
    dns_query_t q = parseada(&p);
    const uint8_t ip[4] = {192, 168, 4, 1};
    TEST_ASSERT_EQUAL_size_t(0, dns_wire_build_a_response(&q, ip, 60, out, 20));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bloqueo_a);
    RUN_TEST(test_bloqueo_aaaa);
    RUN_TEST(test_bloqueo_otro_tipo_sin_datos);
    RUN_TEST(test_bloqueo_con_edns_incluye_opt);
    RUN_TEST(test_bloqueo_buffer_insuficiente);
    RUN_TEST(test_respuesta_servfail);
    RUN_TEST(test_rewrite_id);
    RUN_TEST(test_min_ttl_de_answers);
    RUN_TEST(test_min_ttl_negativa_usa_soa);
    RUN_TEST(test_min_ttl_sin_registros);
    RUN_TEST(test_decrement_ttls_respeta_opt);
    RUN_TEST(test_decrement_ttls_satura_en_cero);
    RUN_TEST(test_truncate_deja_pregunta_y_opt);
    RUN_TEST(test_truncate_sin_opt);
    RUN_TEST(test_a_response_ip_fija);
    RUN_TEST(test_a_response_tipo_no_a_sin_datos);
    RUN_TEST(test_a_response_con_edns);
    RUN_TEST(test_a_response_buffer_insuficiente);
    return UNITY_END();
}
