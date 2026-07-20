/*
 * T010 — tests de blocklist: orden+dedupe, búsqueda por sufijo con límites de
 * etiqueta, fail-open en EMPTY/LOADING (CB-20 unitario) y truncado determinista.
 */
#include <stdio.h>
#include <string.h>

#include "unity.h"

#include "blocklist.h"

void setUp(void) {}
void tearDown(void) {}

static char blob[8192];
static uint32_t idx[256];
static blocklist_t bl;

static void carga(const char *const *doms, size_t n)
{
    blocklist_init(&bl, blob, sizeof(blob), idx, 256);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_TRUE(blocklist_add(&bl, doms[i], strlen(doms[i])));
    }
    blocklist_finalize(&bl);
}

static bool contiene(const char *s) { return blocklist_contains(&bl, s, strlen(s)); }

/* --- fail-open (FR-007 / CB-20) --- */

static void test_vacia_no_bloquea_nada(void)
{
    blocklist_init(&bl, blob, sizeof(blob), idx, 256);
    TEST_ASSERT_FALSE(contiene("com.example"));
}

static void test_cargando_no_bloquea_nada(void)
{
    blocklist_init(&bl, blob, sizeof(blob), idx, 256);
    TEST_ASSERT_TRUE(blocklist_add(&bl, "com.example", 11));
    /* sin finalize: estado LOADING ⇒ reenvío puro */
    TEST_ASSERT_FALSE(contiene("com.example"));
    blocklist_finalize(&bl);
    TEST_ASSERT_TRUE(contiene("com.example"));
}

/* --- coincidencia --- */

static void test_exacto_y_subdominio(void)
{
    const char *d[] = {"com.example"};
    carga(d, 1);
    TEST_ASSERT_TRUE(contiene("com.example"));
    TEST_ASSERT_TRUE(contiene("com.example.ads"));
    TEST_ASSERT_TRUE(contiene("com.example.ads.x.y"));
    TEST_ASSERT_FALSE(contiene("com.examplebad"));
    TEST_ASSERT_FALSE(contiene("com.exampl"));
    TEST_ASSERT_FALSE(contiene("org.example"));
}

static void test_trampa_del_predecesor(void)
{
    /* Con entradas "com.example" y "com.example.a", el predecesor binario de
     * "com.example.zz" es "com.example.a" (no es prefijo) — pero "com.example"
     * SÍ casa. Una implementación que solo mira el predecesor falla aquí. */
    const char *d[] = {"com.example", "com.example.a"};
    carga(d, 2);
    TEST_ASSERT_TRUE(contiene("com.example.zz"));
}

static void test_bloquear_tld_bloquea_todo_debajo(void)
{
    const char *d[] = {"lan"};
    carga(d, 1);
    TEST_ASSERT_TRUE(contiene("lan.impresora"));
    TEST_ASSERT_FALSE(contiene("land.x"));
}

static void test_orden_no_importa_al_cargar(void)
{
    const char *d[] = {"org.zzz", "com.aaa", "net.mmm"};
    carga(d, 3);
    TEST_ASSERT_TRUE(contiene("com.aaa"));
    TEST_ASSERT_TRUE(contiene("net.mmm"));
    TEST_ASSERT_TRUE(contiene("org.zzz"));
    TEST_ASSERT_FALSE(contiene("com.aab"));
}

static void test_dedupe(void)
{
    const char *d[] = {"com.doble", "com.doble", "com.doble"};
    carga(d, 3);
    TEST_ASSERT_EQUAL_UINT32(1, bl.count);
    TEST_ASSERT_TRUE(contiene("com.doble"));
}

static void test_lista_grande(void)
{
    blocklist_init(&bl, blob, sizeof(blob), idx, 256);
    char nombre[32];
    for (int i = 0; i < 200; i++) {
        /* orden de inserción pseudo-desordenado */
        snprintf(nombre, sizeof(nombre), "com.dom%03d", (i * 73) % 200);
        TEST_ASSERT_TRUE(blocklist_add(&bl, nombre, strlen(nombre)));
    }
    blocklist_finalize(&bl);
    TEST_ASSERT_EQUAL_UINT32(200, bl.count);
    for (int i = 0; i < 200; i++) {
        snprintf(nombre, sizeof(nombre), "com.dom%03d", i);
        TEST_ASSERT_TRUE(contiene(nombre));
        snprintf(nombre, sizeof(nombre), "com.dom%03d.sub", i);
        TEST_ASSERT_TRUE(contiene(nombre));
    }
    TEST_ASSERT_FALSE(contiene("com.dom200"));
    TEST_ASSERT_FALSE(contiene("com.dom19"));  /* prefijo textual, no etiqueta */
}

/* --- truncado determinista (P-II) --- */

static void test_truncado_por_blob(void)
{
    static char blob_mini[24];
    blocklist_init(&bl, blob_mini, sizeof(blob_mini), idx, 256);
    TEST_ASSERT_TRUE(blocklist_add(&bl, "com.aaa", 7));  /* 8 bytes con NUL */
    TEST_ASSERT_TRUE(blocklist_add(&bl, "com.bbb", 7));  /* 16 */
    TEST_ASSERT_TRUE(blocklist_add(&bl, "com.ccc", 7));  /* 24: justo */
    TEST_ASSERT_FALSE(blocklist_add(&bl, "com.ddd", 7)); /* no cabe */
    TEST_ASSERT_EQUAL_UINT32(1, bl.truncated);
    blocklist_finalize(&bl);
    TEST_ASSERT_EQUAL_UINT32(3, bl.count);
    TEST_ASSERT_TRUE(contiene("com.ccc"));
    TEST_ASSERT_FALSE(contiene("com.ddd"));
}

static void test_truncado_por_indice(void)
{
    static uint32_t idx_mini[2];
    blocklist_init(&bl, blob, sizeof(blob), idx_mini, 2);
    TEST_ASSERT_TRUE(blocklist_add(&bl, "com.aaa", 7));
    TEST_ASSERT_TRUE(blocklist_add(&bl, "com.bbb", 7));
    TEST_ASSERT_FALSE(blocklist_add(&bl, "com.ccc", 7));
    TEST_ASSERT_FALSE(blocklist_add(&bl, "com.ddd", 7));
    TEST_ASSERT_EQUAL_UINT32(2, bl.truncated);
    blocklist_finalize(&bl);
    TEST_ASSERT_TRUE(contiene("com.aaa"));
    TEST_ASSERT_TRUE(contiene("com.bbb"));
    TEST_ASSERT_FALSE(contiene("com.ccc"));
}

/* --- entradas inválidas --- */

static void test_entrada_vacia_o_nula(void)
{
    blocklist_init(&bl, blob, sizeof(blob), idx, 256);
    TEST_ASSERT_FALSE(blocklist_add(&bl, "", 0));
    TEST_ASSERT_FALSE(blocklist_add(&bl, NULL, 5));
    blocklist_finalize(&bl);
    TEST_ASSERT_FALSE(contiene("com.example"));
    TEST_ASSERT_FALSE(blocklist_contains(&bl, "", 0));
    TEST_ASSERT_FALSE(blocklist_contains(&bl, NULL, 3));
}

/* --- spec 004: reset (reutilizar el buffer) y serialización EBL1 --- */

static void test_reset_reutiliza_buffer(void)
{
    const char *a[] = {"com.example", "net.doubleclick"};
    carga(a, 2);
    TEST_ASSERT_TRUE(contiene("com.example"));

    blocklist_reset(&bl);
    TEST_ASSERT_EQUAL_INT(BL_EMPTY, bl.state);
    TEST_ASSERT_EQUAL_UINT32(0, bl.count);
    TEST_ASSERT_EQUAL_UINT32(0, bl.blob_len);
    TEST_ASSERT_EQUAL_UINT32(0, bl.truncated);
    TEST_ASSERT_FALSE(contiene("com.example")); /* EMPTY ⇒ fail-open */

    /* el mismo buffer se reutiliza para una lista nueva */
    TEST_ASSERT_TRUE(blocklist_add(&bl, "net.tracker", strlen("net.tracker")));
    blocklist_finalize(&bl);
    TEST_ASSERT_TRUE(contiene("net.tracker"));
    TEST_ASSERT_FALSE(contiene("com.example"));
}

/* LB-H2: serializa a EBL1 y verifica formato + orden + round-trip re-cargando */
static void test_serialize_roundtrip(void)
{
    const char *doms[] = {"com.example.ads", "net.doubleclick", "com.example",
                          "com.example"}; /* con duplicado */
    carga(doms, 4);
    uint32_t esperado = bl.count; /* tras dedupe */

    uint8_t out[512];
    size_t n = blocklist_serialize(&bl, out, sizeof(out));
    TEST_ASSERT_TRUE(n > 8);
    TEST_ASSERT_EQUAL_MEMORY("EBL1", out, 4);
    uint32_t count;
    memcpy(&count, out + 4, 4);
    TEST_ASSERT_EQUAL_UINT32(esperado, count);

    /* entradas NUL-terminadas, estrictamente crecientes (ordenadas+dedup) */
    const char *p = (const char *)out + 8;
    const char *prev = NULL;
    for (uint32_t i = 0; i < count; i++) {
        size_t l = strlen(p);
        if (prev != NULL) {
            TEST_ASSERT_TRUE(strcmp(prev, p) < 0);
        }
        prev = p;
        p += l + 1;
    }
    TEST_ASSERT_EQUAL_size_t((size_t)((const uint8_t *)p - out), n);

    /* round-trip: re-cargar desde el buffer serializado ⇒ misma búsqueda */
    static char blob2[8192];
    static uint32_t idx2[256];
    blocklist_t bl2;
    blocklist_init(&bl2, blob2, sizeof(blob2), idx2, 256);
    const char *q = (const char *)out + 8;
    for (uint32_t i = 0; i < count; i++) {
        size_t l = strlen(q);
        TEST_ASSERT_TRUE(blocklist_add(&bl2, q, l));
        q += l + 1;
    }
    blocklist_finalize(&bl2);
    TEST_ASSERT_TRUE(blocklist_contains(&bl2, "com.example", strlen("com.example")));
    TEST_ASSERT_TRUE(blocklist_contains(&bl2, "net.doubleclick", strlen("net.doubleclick")));

    /* buffer que no cabe ⇒ 0 */
    uint8_t tiny[8];
    TEST_ASSERT_EQUAL_size_t(0, blocklist_serialize(&bl, tiny, sizeof(tiny)));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_vacia_no_bloquea_nada);
    RUN_TEST(test_cargando_no_bloquea_nada);
    RUN_TEST(test_exacto_y_subdominio);
    RUN_TEST(test_trampa_del_predecesor);
    RUN_TEST(test_bloquear_tld_bloquea_todo_debajo);
    RUN_TEST(test_orden_no_importa_al_cargar);
    RUN_TEST(test_dedupe);
    RUN_TEST(test_lista_grande);
    RUN_TEST(test_truncado_por_blob);
    RUN_TEST(test_truncado_por_indice);
    RUN_TEST(test_entrada_vacia_o_nula);
    RUN_TEST(test_reset_reutiliza_buffer);
    RUN_TEST(test_serialize_roundtrip);
    return UNITY_END();
}
