/*
 * P04/P06/P08 — tests de provision_logic (PB-H1..H4). Escritos antes de
 * implementar (test-first). La entrada del formulario se trata como hostil.
 */
#include <string.h>

#include "unity.h"

#include "provision_logic.h"

void setUp(void) {}
void tearDown(void) {}

/* --- parseo del formulario (PB-H1) --- */

static prov_creds_t parse(const char *body)
{
    prov_creds_t c;
    memset(&c, 0xAA, sizeof(c));
    TEST_ASSERT_EQUAL_INT(PROV_FORM_OK,
                          provision_form_parse(body, strlen(body), &c));
    return c;
}

static void test_form_basico(void)
{
    prov_creds_t c = parse("ssid=MiRed&pass=secreto123");
    TEST_ASSERT_EQUAL_STRING("MiRed", c.ssid);
    TEST_ASSERT_EQUAL_STRING("secreto123", c.pass);
}

static void test_form_decodifica_mas_y_percent(void)
{
    prov_creds_t c = parse("ssid=Mi+Red&pass=a%20b%21");
    TEST_ASSERT_EQUAL_STRING("Mi Red", c.ssid);
    TEST_ASSERT_EQUAL_STRING("a b!", c.pass);
}

static void test_form_orden_invertido_y_campos_extra(void)
{
    prov_creds_t c = parse("extra=x&pass=clave1234&ssid=Casa&otro=y");
    TEST_ASSERT_EQUAL_STRING("Casa", c.ssid);
    TEST_ASSERT_EQUAL_STRING("clave1234", c.pass);
}

static void test_form_pass_vacio(void)
{
    prov_creds_t c = parse("ssid=Abierta&pass=");
    TEST_ASSERT_EQUAL_STRING("Abierta", c.ssid);
    TEST_ASSERT_EQUAL_STRING("", c.pass);
}

static void test_form_percent_no_ascii(void)
{
    /* %C3%B1 = 'ñ' en UTF-8; se preserva byte a byte */
    prov_creds_t c = parse("ssid=Espa%C3%B1a&pass=clave123");
    TEST_ASSERT_EQUAL_UINT8(0xC3, (uint8_t)c.ssid[4]);
    TEST_ASSERT_EQUAL_UINT8(0xB1, (uint8_t)c.ssid[5]);
}

static void test_form_rechaza_percent_invalido(void)
{
    prov_creds_t c;
    TEST_ASSERT_EQUAL_INT(PROV_FORM_MALFORMED,
                          provision_form_parse("ssid=A%2&pass=x", 14, &c));
    TEST_ASSERT_EQUAL_INT(PROV_FORM_MALFORMED,
                          provision_form_parse("ssid=A%ZZ&pass=x", 16, &c));
    TEST_ASSERT_EQUAL_INT(PROV_FORM_MALFORMED,
                          provision_form_parse("ssid=A%", 7, &c));
}

static void test_form_sin_ssid(void)
{
    prov_creds_t c;
    TEST_ASSERT_EQUAL_INT(PROV_FORM_MALFORMED,
                          provision_form_parse("pass=solopass", 13, &c));
}

static void test_form_sobre_largo(void)
{
    char body[128];
    int n = sprintf(body, "ssid=");
    for (int i = 0; i < 40; i++) {
        body[n++] = 'a'; /* 40 > 32 */
    }
    strcpy(body + n, "&pass=clave123");
    prov_creds_t c;
    TEST_ASSERT_EQUAL_INT(PROV_FORM_TOO_LONG,
                          provision_form_parse(body, strlen(body), &c));
}

static void test_form_fuzz_no_revienta(void)
{
    const char *base = "ssid=Mi+Red&pass=a%20b%21";
    char m[64];
    size_t len = strlen(base);
    for (size_t i = 0; i < len; i++) {
        for (int x = 0; x < 3; x++) {
            memcpy(m, base, len + 1);
            m[i] ^= (uint8_t)(1 << x);
            prov_creds_t c;
            prov_form_err_t r = provision_form_parse(m, len, &c);
            TEST_ASSERT_TRUE(r == PROV_FORM_OK || r == PROV_FORM_MALFORMED ||
                             r == PROV_FORM_TOO_LONG);
        }
    }
    /* prefijos truncados */
    for (size_t l = 0; l <= len; l++) {
        prov_creds_t c;
        (void)provision_form_parse(base, l, &c);
    }
}

/* --- validación (PB-H2) --- */

static bool valida(const char *ssid, const char *pass)
{
    prov_creds_t c;
    memset(&c, 0, sizeof(c));
    strcpy(c.ssid, ssid);
    strcpy(c.pass, pass);
    return provision_creds_valid(&c);
}

static void test_valid_ssid_longitud(void)
{
    char s32[33];
    memset(s32, 'a', 32);
    s32[32] = '\0';
    TEST_ASSERT_TRUE(valida("A", "clave123"));       /* SSID 1 ok */
    TEST_ASSERT_TRUE(valida(s32, "clave123"));       /* SSID 32 ok */
    TEST_ASSERT_FALSE(valida("", "clave123"));       /* SSID 0 no */
}

static void test_valid_pass_wpa2(void)
{
    TEST_ASSERT_TRUE(valida("Red", ""));             /* abierta */
    TEST_ASSERT_TRUE(valida("Red", "12345678"));     /* 8 ok */
    char p63[64];
    memset(p63, 'x', 63);
    p63[63] = '\0';
    TEST_ASSERT_TRUE(valida("Red", p63));            /* 63 ok */
    TEST_ASSERT_FALSE(valida("Red", "1234567"));     /* 7 no */
}

static void test_valid_rechaza_control_en_ssid(void)
{
    char s[8] = {'A', 'B', 0x01, 'C', '\0'};
    prov_creds_t c;
    memset(&c, 0, sizeof(c));
    memcpy(c.ssid, s, 5);
    strcpy(c.pass, "clave123");
    TEST_ASSERT_FALSE(provision_creds_valid(&c));
}

/* --- SSID del AP desde el MAC (no secreto) (PB-H3) --- */

static void test_ap_ssid_desde_mac(void)
{
    const uint8_t a[6] = {0x24, 0x6F, 0x28, 0x00, 0x4A, 0x9C};
    const uint8_t b[6] = {0x24, 0x6F, 0x28, 0x11, 0x22, 0x33};
    char sa[16], sb[16];
    provision_ap_ssid(a, sa);
    provision_ap_ssid(b, sb);
    TEST_ASSERT_EQUAL_STRING("ESPHole-4A9C", sa);
    TEST_ASSERT_EQUAL_STRING("ESPHole-2233", sb);
}

/* --- clave WPA2 desde bytes aleatorios (NO del MAC público) (PB-H3) --- */

static void test_ap_pass_codifica_imprimible(void)
{
    const uint8_t r[8] = {0x00, 0xFF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    char pass[16];
    provision_ap_pass(r, pass);
    size_t pl = strlen(pass);
    TEST_ASSERT_TRUE(pl >= 8 && pl <= 12);
    for (size_t i = 0; i < pl; i++) {
        TEST_ASSERT_TRUE((uint8_t)pass[i] >= 33 && (uint8_t)pass[i] <= 126);
    }
}

static void test_ap_pass_distinta_por_bytes(void)
{
    const uint8_t r1[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t r2[8] = {1, 2, 3, 4, 5, 6, 7, 9}; /* un byte distinto */
    char p1[16], p2[16], p1b[16];
    provision_ap_pass(r1, p1);
    provision_ap_pass(r2, p2);
    provision_ap_pass(r1, p1b);
    TEST_ASSERT_TRUE(strcmp(p1, p2) != 0);  /* bytes distintos → clave distinta */
    TEST_ASSERT_EQUAL_STRING(p1, p1b);      /* determinista dado el mismo input */
}

static void test_ap_pass_todo_ceros_valida(void)
{
    /* caso degenerado: aun con bytes todo-cero, la clave es imprimible y válida */
    const uint8_t r[8] = {0};
    char pass[16];
    provision_ap_pass(r, pass);
    TEST_ASSERT_TRUE(strlen(pass) >= 8);
    for (size_t i = 0; pass[i]; i++) {
        TEST_ASSERT_TRUE((uint8_t)pass[i] >= 33 && (uint8_t)pass[i] <= 126);
    }
}

/* --- decisión de arranque (PB-H4) --- */

static void test_decide_boot_tabla(void)
{
    /* boot_held siempre PROVISION */
    TEST_ASSERT_EQUAL_INT(PROV_MODE_PROVISION, provision_decide_boot(true, true, true));
    TEST_ASSERT_EQUAL_INT(PROV_MODE_PROVISION, provision_decide_boot(false, false, true));
    /* sin creds siempre PROVISION */
    TEST_ASSERT_EQUAL_INT(PROV_MODE_PROVISION, provision_decide_boot(false, false, false));
    TEST_ASSERT_EQUAL_INT(PROV_MODE_PROVISION, provision_decide_boot(false, true, false));
    /* con creds y sin botón → CONNECTING (con prov 0 y 1) */
    TEST_ASSERT_EQUAL_INT(PROV_MODE_CONNECTING, provision_decide_boot(true, false, false));
    TEST_ASSERT_EQUAL_INT(PROV_MODE_CONNECTING, provision_decide_boot(true, true, false));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_form_basico);
    RUN_TEST(test_form_decodifica_mas_y_percent);
    RUN_TEST(test_form_orden_invertido_y_campos_extra);
    RUN_TEST(test_form_pass_vacio);
    RUN_TEST(test_form_percent_no_ascii);
    RUN_TEST(test_form_rechaza_percent_invalido);
    RUN_TEST(test_form_sin_ssid);
    RUN_TEST(test_form_sobre_largo);
    RUN_TEST(test_form_fuzz_no_revienta);
    RUN_TEST(test_valid_ssid_longitud);
    RUN_TEST(test_valid_pass_wpa2);
    RUN_TEST(test_valid_rechaza_control_en_ssid);
    RUN_TEST(test_ap_ssid_desde_mac);
    RUN_TEST(test_ap_pass_codifica_imprimible);
    RUN_TEST(test_ap_pass_distinta_por_bytes);
    RUN_TEST(test_ap_pass_todo_ceros_valida);
    RUN_TEST(test_decide_boot_tabla);
    return UNITY_END();
}
