/*
 * Tests host de hostlist_parse_line (spec 004, contrato HL-01..HL-11).
 * Toda línea es hostil: corre bajo ASan/UBSan.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "hostlist.h"

void setUp(void) {}
void tearDown(void) {}

/* Comprueba que la línea aporta 'esperado' como dominio. */
static void dom_es(const char *line, const char *esperado)
{
    const char *dom = NULL;
    size_t dl = 0;
    TEST_ASSERT_TRUE(hostlist_parse_line(line, strlen(line), &dom, &dl));
    TEST_ASSERT_EQUAL_size_t(strlen(esperado), dl);
    TEST_ASSERT_EQUAL_MEMORY(esperado, dom, dl);
    /* dom apunta DENTRO de line */
    TEST_ASSERT_TRUE(dom >= line && dom + dl <= line + strlen(line));
}

static void se_ignora(const char *line)
{
    const char *dom = NULL;
    size_t dl = 0;
    TEST_ASSERT_FALSE(hostlist_parse_line(line, strlen(line), &dom, &dl));
}

/* HL-01/02: formato HOSTS, dominio en el 2º campo */
static void test_hosts_ipv4(void)
{
    dom_es("0.0.0.0 ads.example.com", "ads.example.com");
    dom_es("127.0.0.1 tracker.net", "tracker.net");
}

/* HL-03: lista plana, dominio en el 1º campo */
static void test_lista_plana(void)
{
    dom_es("plaindomain.org", "plaindomain.org");
}

/* HL-04: comentario en línea recortado */
static void test_comentario_en_linea(void)
{
    dom_es("0.0.0.0 doubleclick.net # anuncio", "doubleclick.net");
    dom_es("plaindomain.org#sin-espacio", "plaindomain.org");
}

/* HL-05: comentarios, vacías y solo-blancos se ignoran */
static void test_ignora_vacias_y_comentarios(void)
{
    se_ignora("# comentario");
    se_ignora("   # con sangría");
    se_ignora("");
    se_ignora("   ");
    se_ignora("\t\t");
}

/* HL-06/07/08: pseudo-dominios de sistema excluidos */
static void test_excluye_sistema(void)
{
    se_ignora("0.0.0.0 localhost");
    se_ignora("127.0.0.1 localhost.localdomain");
    se_ignora("::1 ip6-localhost");
    se_ignora("ff02::2 ip6-allrouters");
    se_ignora("255.255.255.255 broadcasthost");
    se_ignora("0.0.0.0"); /* un solo campo y además es 0.0.0.0 */
}

/* HL-09: tabuladores y espacios alrededor */
static void test_espacios_y_tabs(void)
{
    dom_es("  0.0.0.0\tspaced.example.com\t\t", "spaced.example.com");
    dom_es("\t127.0.0.1   tabbed.net  ", "tabbed.net");
}

/* mayúsculas: la exclusión es case-insensitive; un dominio normal se
 * devuelve tal cual (sin bajar a minúsculas: eso es de normalize_invert) */
static void test_case(void)
{
    se_ignora("0.0.0.0 LocalHost");
    dom_es("0.0.0.0 CDN.Example.COM", "CDN.Example.COM");
}

/* HL-10: seguridad de rango — buffer SIN NUL-terminar, longitud exacta.
 * ASan detectaría cualquier lectura fuera de [line, line+len). */
static void test_sin_nul_terminar(void)
{
    const char *fuente = "0.0.0.0 edge.example.net";
    size_t n = strlen(fuente);
    char *buf = malloc(n); /* exactamente n, sin '\0' */
    memcpy(buf, fuente, n);
    const char *dom = NULL;
    size_t dl = 0;
    TEST_ASSERT_TRUE(hostlist_parse_line(buf, n, &dom, &dl));
    TEST_ASSERT_EQUAL_size_t(strlen("edge.example.net"), dl);
    TEST_ASSERT_EQUAL_MEMORY("edge.example.net", dom, dl);
    free(buf);
}

/* len==0 → false */
static void test_len_cero(void)
{
    const char *dom = NULL;
    size_t dl = 0;
    TEST_ASSERT_FALSE(hostlist_parse_line("x", 0, &dom, &dl));
}

/* HL-11: mini-fuzz — mutaciones de una base; nunca lee fuera de rango (ASan) */
static void test_fuzz_mutaciones(void)
{
    const char base[] = "0.0.0.0 fuzz.example.com # c";
    size_t n = sizeof(base) - 1;
    for (size_t i = 0; i < n; i++) {
        for (int b = 0; b < 256; b += 17) {
            char *buf = malloc(n);
            memcpy(buf, base, n);
            buf[i] = (char)b; /* muta un byte */
            const char *dom = NULL;
            size_t dl = 0;
            bool r = hostlist_parse_line(buf, n, &dom, &dl);
            if (r) {
                /* si acepta, la salida está dentro del buffer */
                TEST_ASSERT_TRUE(dom >= buf && dom + dl <= buf + n);
            }
            free(buf);
        }
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_hosts_ipv4);
    RUN_TEST(test_lista_plana);
    RUN_TEST(test_comentario_en_linea);
    RUN_TEST(test_ignora_vacias_y_comentarios);
    RUN_TEST(test_excluye_sistema);
    RUN_TEST(test_espacios_y_tabs);
    RUN_TEST(test_case);
    RUN_TEST(test_sin_nul_terminar);
    RUN_TEST(test_len_cero);
    RUN_TEST(test_fuzz_mutaciones);
    return UNITY_END();
}
