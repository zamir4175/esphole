/*
 * Tests host de dot_frame (spec 007, contrato dot-frame.md DF-01..08).
 * RFC 7858: prefijo de longitud de 2 bytes + validación de la respuesta del
 * resolvedor (id + pregunta). Toda respuesta es hostil: ASan/UBSan.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "dot_frame.h"

void setUp(void) {}
void tearDown(void) {}

/* --- helpers: construir mensajes DNS wire --- */

/*
 * Escribe cabecera (id, flags) + una pregunta (qname "www.example.com" u otra)
 * con qtype/qclass en 'buf'. QR = bit alto de flags. Devuelve la longitud total.
 * name: presentación separada por puntos.
 */
static size_t mk_msg(uint8_t *buf, uint16_t id, uint16_t flags, const char *name,
                     uint16_t qtype, uint16_t qclass)
{
    buf[0] = (uint8_t)(id >> 8);
    buf[1] = (uint8_t)id;
    buf[2] = (uint8_t)(flags >> 8);
    buf[3] = (uint8_t)flags;
    buf[4] = 0;
    buf[5] = 1; /* QDCOUNT = 1 */
    memset(buf + 6, 0, 6); /* AN/NS/AR = 0 */
    size_t p = 12;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, s, l);
        p += l;
        s += l;
        if (dot) s++;
    }
    buf[p++] = 0; /* raíz */
    buf[p++] = (uint8_t)(qtype >> 8);
    buf[p++] = (uint8_t)qtype;
    buf[p++] = (uint8_t)(qclass >> 8);
    buf[p++] = (uint8_t)qclass;
    return p;
}

/* DF-01: prefix de un mensaje de N bytes → [N_hi][N_lo][msg], devuelve N+2 */
static void test_prefix_ok(void)
{
    uint8_t msg[8] = {0xde, 0xad, 1, 2, 3, 4, 5, 6};
    uint8_t out[16];
    size_t n = dot_frame_prefix(msg, sizeof(msg), out, sizeof(out));
    TEST_ASSERT_EQUAL_UINT(sizeof(msg) + 2, n);
    TEST_ASSERT_EQUAL_UINT8(0, out[0]);
    TEST_ASSERT_EQUAL_UINT8(8, out[1]);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg, out + 2, sizeof(msg));
}

/* DF-01b: longitud >255 codifica bien el byte alto */
static void test_prefix_big_len(void)
{
    static uint8_t msg[300];
    static uint8_t out[302];
    memset(msg, 0xAB, sizeof(msg));
    size_t n = dot_frame_prefix(msg, sizeof(msg), out, sizeof(out));
    TEST_ASSERT_EQUAL_UINT(sizeof(msg) + 2, n);
    TEST_ASSERT_EQUAL_UINT8(300 >> 8, out[0]); /* 0x01 */
    TEST_ASSERT_EQUAL_UINT8(300 & 0xff, out[1]); /* 0x2c */
}

/* DF-02: cap corto → 0, sin desbordar */
static void test_prefix_cap_short(void)
{
    uint8_t msg[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t out[9]; /* necesita 10 */
    TEST_ASSERT_EQUAL_UINT(0, dot_frame_prefix(msg, sizeof(msg), out, sizeof(out)));
}

/* DF-02b: len no cabe en 16 bits → 0 */
static void test_prefix_len_overflow(void)
{
    uint8_t dummy = 0;
    /* len ficticio > 0xffff; no se lee msg (cap 0 fuerza el rechazo antes) */
    TEST_ASSERT_EQUAL_UINT(0, dot_frame_prefix(&dummy, 0x10000, NULL, 0x10002));
}

/* DF-03: respuesta con mismo id y misma pregunta → true */
static void test_response_ok(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1); /* QR=0, RD=1 */
    size_t rn = mk_msg(r, 0x1234, 0x8180, "www.example.com", 1, 1); /* QR=1 */
    TEST_ASSERT_TRUE(dot_response_ok(q, qn, r, rn));
}

/* DF-04: id distinto → false */
static void test_response_bad_id(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);
    size_t rn = mk_msg(r, 0x9999, 0x8180, "www.example.com", 1, 1);
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, rn));
}

/* DF-05: pregunta distinta (qname) → false */
static void test_response_bad_qname(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);
    size_t rn = mk_msg(r, 0x1234, 0x8180, "www.evil.com", 1, 1);
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, rn));
}

/* DF-05b: pregunta distinta (qtype) → false */
static void test_response_bad_qtype(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);   /* A */
    size_t rn = mk_msg(r, 0x1234, 0x8180, "www.example.com", 28, 1);  /* AAAA */
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, rn));
}

/* DF-06: respuesta sin bit QR (es una consulta) → false */
static void test_response_no_qr(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);
    size_t rn = mk_msg(r, 0x1234, 0x0100, "www.example.com", 1, 1); /* QR=0 */
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, rn));
}

/* DF-07: truncada / demasiado corta → false, sin overread */
static void test_response_truncated(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);
    (void)mk_msg(r, 0x1234, 0x8180, "www.example.com", 1, 1);
    /* respuesta cortada a la mitad de la pregunta */
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, 14));
    /* ambos < 12 */
    TEST_ASSERT_FALSE(dot_response_ok(q, 4, r, 4));
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, 0));
}

/* DF-07b: qname con longitud de etiqueta que se sale del buffer → false */
static void test_response_label_overrun(void)
{
    uint8_t q[64], r[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);
    (void)mk_msg(r, 0x1234, 0x8180, "www.example.com", 1, 1);
    /* corromper la primera longitud de etiqueta a un valor enorme */
    r[12] = 0x3f; /* 63 bytes, pero recortamos la respuesta para que se salga */
    TEST_ASSERT_FALSE(dot_response_ok(q, qn, r, 20));
}

/* DF-08: mini-fuzz — mutar cada byte de una respuesta válida no desborda */
static void test_response_fuzz(void)
{
    uint8_t q[64], r[64], m[64];
    size_t qn = mk_msg(q, 0x1234, 0x0100, "www.example.com", 1, 1);
    size_t rn = mk_msg(r, 0x1234, 0x8180, "www.example.com", 1, 1);
    for (size_t i = 0; i < rn; i++) {
        for (int b = 0; b < 256; b += 17) {
            memcpy(m, r, rn);
            m[i] = (uint8_t)b;
            /* no debe leer fuera de rango; el valor de retorno da igual */
            (void)dot_response_ok(q, qn, m, rn);
            /* también con longitudes recortadas */
            (void)dot_response_ok(q, qn, m, i + 1);
        }
    }
    TEST_PASS();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_prefix_ok);
    RUN_TEST(test_prefix_big_len);
    RUN_TEST(test_prefix_cap_short);
    RUN_TEST(test_prefix_len_overflow);
    RUN_TEST(test_response_ok);
    RUN_TEST(test_response_bad_id);
    RUN_TEST(test_response_bad_qname);
    RUN_TEST(test_response_bad_qtype);
    RUN_TEST(test_response_no_qr);
    RUN_TEST(test_response_truncated);
    RUN_TEST(test_response_label_overrun);
    RUN_TEST(test_response_fuzz);
    return UNITY_END();
}
