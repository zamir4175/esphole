/*
 * T004 — tests de domain (module-interfaces.md §2, FR-015, casos de C2).
 * Escritos ANTES de la implementación (test-first, Principio IX).
 */
#include <string.h>

#include "unity.h"

#include "domain.h"

void setUp(void) {}
void tearDown(void) {}

static char out[ESPHOLE_DOMAIN_MAX + 1];

static int ni(const char *s)
{
    memset(out, 0xAA, sizeof(out)); /* detectar escrituras a medias */
    return domain_normalize_invert(s, strlen(s), out);
}

/* --- normalización + inversión --- */

static void test_invierte_dominio_basico(void)
{
    TEST_ASSERT_EQUAL_INT(15, ni("ads.example.com"));
    TEST_ASSERT_EQUAL_STRING("com.example.ads", out);
}

static void test_normaliza_mayusculas(void)
{
    TEST_ASSERT_EQUAL_INT(15, ni("Ads.Example.COM"));
    TEST_ASSERT_EQUAL_STRING("com.example.ads", out);
}

static void test_admite_punto_final(void)
{
    TEST_ASSERT_EQUAL_INT(11, ni("example.com."));
    TEST_ASSERT_EQUAL_STRING("com.example", out);
}

static void test_etiqueta_unica(void)
{
    TEST_ASSERT_EQUAL_INT(9, ni("localhost"));
    TEST_ASSERT_EQUAL_STRING("localhost", out);
}

static void test_inversion_es_involutiva(void)
{
    char primera[ESPHOLE_DOMAIN_MAX + 1];
    TEST_ASSERT_EQUAL_INT(15, ni("ads.example.com"));
    memcpy(primera, out, sizeof(primera));
    TEST_ASSERT_EQUAL_INT(15, ni(primera));
    TEST_ASSERT_EQUAL_STRING("ads.example.com", out);
}

static void test_acepta_digitos_guion_y_guion_bajo(void)
{
    TEST_ASSERT_EQUAL_INT(26, ni("_dmarc.mail-01.example.com"));
    TEST_ASSERT_EQUAL_STRING("com.example.mail-01._dmarc", out);
}

static void test_longitud_maxima_exacta(void)
{
    /* 63 + '.' + 63 + '.' + 63 + '.' + 61 = 253 */
    char nombre[ESPHOLE_DOMAIN_MAX + 2];
    memset(nombre, 'a', 63);
    nombre[63] = '.';
    memset(nombre + 64, 'b', 63);
    nombre[127] = '.';
    memset(nombre + 128, 'c', 63);
    nombre[191] = '.';
    memset(nombre + 192, 'd', 61);
    nombre[253] = '\0';
    TEST_ASSERT_EQUAL_INT(253, ni(nombre));
}

/* --- rechazos --- */

static void test_rechaza_vacio_y_solo_punto(void)
{
    TEST_ASSERT_EQUAL_INT(-1, ni(""));
    TEST_ASSERT_EQUAL_INT(-1, ni("."));
}

static void test_rechaza_etiqueta_vacia_interna(void)
{
    TEST_ASSERT_EQUAL_INT(-1, ni("a..com"));
    TEST_ASSERT_EQUAL_INT(-1, ni(".example.com"));
}

static void test_rechaza_etiqueta_de_64(void)
{
    char nombre[64 + 4 + 1];
    memset(nombre, 'a', 64);
    memcpy(nombre + 64, ".com", 5);
    TEST_ASSERT_EQUAL_INT(-1, ni(nombre));
    /* y 63 sí es válido */
    memmove(nombre + 63, ".com", 5);
    TEST_ASSERT_EQUAL_INT(63 + 4, ni(nombre));
}

static void test_rechaza_longitud_254(void)
{
    char nombre[ESPHOLE_DOMAIN_MAX + 3];
    memset(nombre, 'a', 63);
    nombre[63] = '.';
    memset(nombre + 64, 'b', 63);
    nombre[127] = '.';
    memset(nombre + 128, 'c', 63);
    nombre[191] = '.';
    memset(nombre + 192, 'd', 62);
    nombre[254] = '\0';
    TEST_ASSERT_EQUAL_INT(-1, ni(nombre));
}

static void test_rechaza_charset_invalido(void)
{
    TEST_ASSERT_EQUAL_INT(-1, ni("exa mple.com"));
    TEST_ASSERT_EQUAL_INT(-1, ni("exam!ple.com"));
    TEST_ASSERT_EQUAL_INT(-1, ni("ex\xc3\xa1mple.com")); /* no-ASCII cruda */
}

/* --- coincidencia por sufijo (FR-015 / C2) --- */

static void test_match_dominio_exacto(void)
{
    TEST_ASSERT_TRUE(domain_suffix_match("com.example", 11, "com.example", 11));
}

static void test_match_subdominio(void)
{
    TEST_ASSERT_TRUE(domain_suffix_match("com.example", 11, "com.example.ads", 15));
}

static void test_no_match_sufijo_solo_textual(void)
{
    /* el caso canónico del spec: notexample.com NO se bloquea */
    TEST_ASSERT_FALSE(domain_suffix_match("com.example", 11, "com.examplebad", 14));
    TEST_ASSERT_FALSE(domain_suffix_match("com.example", 11, "com.example2.ads", 16));
}

static void test_no_match_entrada_mas_larga(void)
{
    TEST_ASSERT_FALSE(domain_suffix_match("com.example.ads", 15, "com.example", 11));
}

static void test_no_match_entrada_vacia(void)
{
    TEST_ASSERT_FALSE(domain_suffix_match("", 0, "com.example", 11));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_invierte_dominio_basico);
    RUN_TEST(test_normaliza_mayusculas);
    RUN_TEST(test_admite_punto_final);
    RUN_TEST(test_etiqueta_unica);
    RUN_TEST(test_inversion_es_involutiva);
    RUN_TEST(test_acepta_digitos_guion_y_guion_bajo);
    RUN_TEST(test_longitud_maxima_exacta);
    RUN_TEST(test_rechaza_vacio_y_solo_punto);
    RUN_TEST(test_rechaza_etiqueta_vacia_interna);
    RUN_TEST(test_rechaza_etiqueta_de_64);
    RUN_TEST(test_rechaza_longitud_254);
    RUN_TEST(test_rechaza_charset_invalido);
    RUN_TEST(test_match_dominio_exacto);
    RUN_TEST(test_match_subdominio);
    RUN_TEST(test_no_match_sufijo_solo_textual);
    RUN_TEST(test_no_match_entrada_mas_larga);
    RUN_TEST(test_no_match_entrada_vacia);
    return UNITY_END();
}
