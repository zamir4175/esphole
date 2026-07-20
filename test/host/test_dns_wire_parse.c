/*
 * T006 — tests de dns_wire_parse_query (RFC 1035/6891; CB-40 unitario).
 * Los paquetes se construyen a mano byte a byte: el parser jamás ve una
 * estructura, solo un buffer hostil.
 */
#include <string.h>

#include "unity.h"

#include "dns_wire.h"
#include "wire_helpers.h"

void setUp(void) {}
void tearDown(void) {}

/* --- parseo válido --- */

static void test_parse_consulta_a_valida(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p.b, p.len, &q));
    TEST_ASSERT_EQUAL_HEX16(0x1234, q.id);
    TEST_ASSERT_EQUAL_STRING("example.com", q.qname);
    TEST_ASSERT_EQUAL_UINT8(11, q.qname_len);
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_A, q.qtype);
    TEST_ASSERT_EQUAL_UINT16(DNS_CLASS_IN, q.qclass);
    TEST_ASSERT_FALSE(q.edns_present);
    TEST_ASSERT_EQUAL_UINT16(512, dns_wire_edns_payload(&q));
    TEST_ASSERT_EQUAL_UINT16(12 + 13 + 4, q.question_end);
    TEST_ASSERT_EQUAL_PTR(p.b, q.raw);
    TEST_ASSERT_EQUAL_UINT16(p.len, q.raw_len);
}

static void test_normaliza_mayusculas_del_wire(void)
{
    pkt_t p = consulta("ExAmPlE.CoM", DNS_TYPE_AAAA);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p.b, p.len, &q));
    TEST_ASSERT_EQUAL_STRING("example.com", q.qname);
}

static void test_parse_con_opt(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[11] = 1; /* ARCOUNT = 1 */
    popt(&p, 1232);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p.b, p.len, &q));
    TEST_ASSERT_TRUE(q.edns_present);
    TEST_ASSERT_EQUAL_UINT16(1232, q.edns_payload);
    TEST_ASSERT_EQUAL_UINT16(1232, dns_wire_edns_payload(&q));
}

static void test_opt_payload_menor_de_512_se_eleva(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[11] = 1;
    popt(&p, 200);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p.b, p.len, &q));
    TEST_ASSERT_EQUAL_UINT16(512, dns_wire_edns_payload(&q));
}

/* --- bien formadas pero no procesables (reenviar íntegras, FR-006) --- */

static void test_qdcount_distinto_de_uno(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[5] = 0; /* QDCOUNT = 0 */
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_UNSUPPORTED, dns_wire_parse_query(p.b, p.len, &q));
    p.b[5] = 2; /* QDCOUNT = 2 */
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_UNSUPPORTED, dns_wire_parse_query(p.b, p.len, &q));
    /* el passthrough (FR-006) necesita id y raw también en UNSUPPORTED:
     * la respuesta relayada debe llevar el ID del cliente (CB-17) */
    TEST_ASSERT_EQUAL_HEX16(0x1234, q.id);
    TEST_ASSERT_EQUAL_PTR(p.b, q.raw);
    TEST_ASSERT_EQUAL_UINT16(p.len, q.raw_len);
}

static void test_opcode_distinto_de_query(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[2] |= 0x10; /* OPCODE = 2 (STATUS) */
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_UNSUPPORTED, dns_wire_parse_query(p.b, p.len, &q));
}

static void test_nombre_raiz(void)
{
    pkt_t p = {.len = 0};
    pheader(&p, 1, 0x0100, 1, 0, 0, 0);
    p8(&p, 0); /* raíz */
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_UNSUPPORTED, dns_wire_parse_query(p.b, p.len, &q));
}

/* --- malformadas (descartar, FR-009 / CB-40) --- */

static void test_paquete_demasiado_corto(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, 0, &q));
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, 11, &q));
}

static void test_respuesta_recibida_como_consulta(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[2] |= 0x80; /* QR = 1 */
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len, &q));
}

static void test_etiqueta_con_bits_reservados(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[12] = 0x40; /* 01xxxxxx: reservado */
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len, &q));
}

static void test_puntero_de_compresion_en_pregunta(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    p.b[12] = 0xC0; /* puntero: no permitido en la pregunta de un cliente */
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len, &q));
}

static void test_etiqueta_desborda_el_paquete(void)
{
    pkt_t p = {.len = 0};
    pheader(&p, 1, 0x0100, 1, 0, 0, 0);
    p8(&p, 30); /* etiqueta de 30 pero solo siguen 3 bytes */
    p8(&p, 'a');
    p8(&p, 'b');
    p8(&p, 'c');
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len, &q));
}

static void test_nombre_total_mayor_de_253(void)
{
    /* 4 etiquetas de 63 → 255 en presentación: demasiado largo */
    char nombre[256];
    char *w = nombre;
    for (int i = 0; i < 4; i++) {
        if (i > 0) {
            *w++ = '.';
        }
        memset(w, 'a' + i, 63);
        w += 63;
    }
    *w = '\0';
    pkt_t p = consulta(nombre, DNS_TYPE_A);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len, &q));
}

static void test_pregunta_sin_qtype_qclass(void)
{
    pkt_t p = consulta("example.com", DNS_TYPE_A);
    dns_query_t q;
    /* recorta los 4 bytes de qtype/qclass */
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len - 4, &q));
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_MALFORMED, dns_wire_parse_query(p.b, p.len - 3, &q));
}

/* --- fuzz determinista: mutaciones nunca provocan crash ni valor fuera de rango --- */

static void test_fuzz_mutaciones_byte_a_byte(void)
{
    pkt_t base = consulta("sub.example.com", DNS_TYPE_A);
    base.b[11] = 1;
    popt(&base, 1232);

    const uint8_t xors[] = {0x01, 0x80, 0xFF};
    for (size_t i = 0; i < base.len; i++) {
        for (size_t x = 0; x < sizeof(xors); x++) {
            pkt_t m = base;
            m.b[i] ^= xors[x];
            dns_query_t q;
            dns_wire_err_t r = dns_wire_parse_query(m.b, m.len, &q);
            TEST_ASSERT_TRUE(r == DNS_WIRE_OK || r == DNS_WIRE_MALFORMED ||
                             r == DNS_WIRE_UNSUPPORTED);
        }
    }
    /* y todos los prefijos truncados */
    for (size_t l = 0; l <= base.len; l++) {
        dns_query_t q;
        dns_wire_err_t r = dns_wire_parse_query(base.b, l, &q);
        TEST_ASSERT_TRUE(r == DNS_WIRE_OK || r == DNS_WIRE_MALFORMED ||
                         r == DNS_WIRE_UNSUPPORTED);
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_consulta_a_valida);
    RUN_TEST(test_normaliza_mayusculas_del_wire);
    RUN_TEST(test_parse_con_opt);
    RUN_TEST(test_opt_payload_menor_de_512_se_eleva);
    RUN_TEST(test_qdcount_distinto_de_uno);
    RUN_TEST(test_opcode_distinto_de_query);
    RUN_TEST(test_nombre_raiz);
    RUN_TEST(test_paquete_demasiado_corto);
    RUN_TEST(test_respuesta_recibida_como_consulta);
    RUN_TEST(test_etiqueta_con_bits_reservados);
    RUN_TEST(test_puntero_de_compresion_en_pregunta);
    RUN_TEST(test_etiqueta_desborda_el_paquete);
    RUN_TEST(test_nombre_total_mayor_de_253);
    RUN_TEST(test_pregunta_sin_qtype_qclass);
    RUN_TEST(test_fuzz_mutaciones_byte_a_byte);
    return UNITY_END();
}
