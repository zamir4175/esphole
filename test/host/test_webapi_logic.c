/*
 * W02/W04/W06/W08/W10 — tests de webapi_logic (AB-H1..H5). Test-first.
 * La entrada de la API se trata como hostil (ASan/UBSan).
 */
#include <string.h>

#include "unity.h"

#include "webapi_logic.h"

void setUp(void) {}
void tearDown(void) {}

/* --- serialización de estado (AB-H1) --- */

static void test_status_json_campos(void)
{
    metrics_snapshot_t m = {0};
    m.contador[MET_TOTAL] = 1000;
    m.contador[MET_BLOQUEADAS] = 250;
    m.contador[MET_CACHE_HITS] = 400;
    m.contador[MET_REENVIADAS] = 350;
    m.contador[MET_SERVFAIL] = 3;
    m.latencia_hist[0] = 500;
    m.latencia_hist[3] = 20;
    m.latencia_inline_max_us = 72;
    m.upstream_fallos[1] = 5;

    webapi_sysinfo_t sys = {0};
    sys.heap_libre = 253000;
    sys.uptime_s = 3661;
    sys.upstreams.count = 2;
    sys.upstreams.salud[0] = 0;
    sys.upstreams.salud[1] = 2;

    char buf[1024];
    size_t n = webapi_status_json(&m, &sys, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_size_t(strlen(buf), n);

    /* campos esperados presentes con sus valores */
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"total\":1000"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"bloqueadas\":250"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"cache_hits\":400"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"reenviadas\":350"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"servfail\":3"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"heap_libre\":253000"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"uptime_s\":3661"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"latencia_inline_max_us\":72"));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"latencia_hist\":[500,"));
    /* salud de upstreams como array */
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"upstreams_salud\":[0,2]"));
    /* objeto JSON bien delimitado */
    TEST_ASSERT_EQUAL_CHAR('{', buf[0]);
    TEST_ASSERT_EQUAL_CHAR('}', buf[n - 1]);
}

static void test_status_json_buffer_corto(void)
{
    metrics_snapshot_t m = {0};
    webapi_sysinfo_t sys = {0};
    char buf[16];
    TEST_ASSERT_EQUAL_size_t(0, webapi_status_json(&m, &sys, buf, sizeof(buf)));
}

static void test_config_json_upstreams(void)
{
    esphole_config_t cfg = {0};
    cfg.upstream_count = 2;
    cfg.upstream_addr[0].family = ESPHOLE_AF_V4;
    cfg.upstream_addr[0].bytes[0] = 1;
    cfg.upstream_addr[0].bytes[1] = 1;
    cfg.upstream_addr[0].bytes[2] = 1;
    cfg.upstream_addr[0].bytes[3] = 1;
    cfg.upstream_addr[1].family = ESPHOLE_AF_V4;
    cfg.upstream_addr[1].bytes[0] = 9;
    cfg.upstream_addr[1].bytes[1] = 9;
    cfg.upstream_addr[1].bytes[2] = 9;
    cfg.upstream_addr[1].bytes[3] = 9;

    char buf[512];
    size_t n = webapi_config_json(&cfg, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"1.1.1.1\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"9.9.9.9\""));
    TEST_ASSERT_NOT_NULL(strstr(buf, "\"upstreams\""));
}

static void test_config_json_v6(void)
{
    esphole_config_t cfg = {0};
    cfg.upstream_count = 1;
    /* 2606:4700:4700::1111 */
    cfg.upstream_addr[0].family = ESPHOLE_AF_V6;
    uint8_t v6[16] = {0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0,
                      0, 0, 0, 0, 0, 0, 0x11, 0x11};
    memcpy(cfg.upstream_addr[0].bytes, v6, 16);
    char buf[512];
    size_t n = webapi_config_json(&cfg, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_NOT_NULL(strstr(buf, "2606:4700:4700::1111"));
}

/* --- parseo/validación de upstreams (AB-H2) --- */

static void test_parse_upstreams_v4(void)
{
    esphole_config_t cfg = {0};
    const char *body = "{\"upstreams\":[\"1.1.1.1\",\"9.9.9.9\"]}";
    TEST_ASSERT_EQUAL_INT(WEBAPI_CFG_OK,
                          webapi_parse_upstreams(body, strlen(body), &cfg));
    TEST_ASSERT_EQUAL_UINT8(2, cfg.upstream_count);
    TEST_ASSERT_EQUAL_UINT8(ESPHOLE_AF_V4, cfg.upstream_addr[0].family);
    TEST_ASSERT_EQUAL_UINT8(1, cfg.upstream_addr[0].bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(9, cfg.upstream_addr[1].bytes[0]);
    TEST_ASSERT_EQUAL_UINT16(53, cfg.upstream_port[0]); /* puerto por defecto */
}

static void test_parse_upstreams_v6(void)
{
    esphole_config_t cfg = {0};
    const char *body = "{\"upstreams\":[\"2606:4700:4700::1111\"]}";
    TEST_ASSERT_EQUAL_INT(WEBAPI_CFG_OK,
                          webapi_parse_upstreams(body, strlen(body), &cfg));
    TEST_ASSERT_EQUAL_UINT8(1, cfg.upstream_count);
    TEST_ASSERT_EQUAL_UINT8(ESPHOLE_AF_V6, cfg.upstream_addr[0].family);
    TEST_ASSERT_EQUAL_UINT8(0x26, cfg.upstream_addr[0].bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(0x11, cfg.upstream_addr[0].bytes[14]);
    TEST_ASSERT_EQUAL_UINT8(0x11, cfg.upstream_addr[0].bytes[15]);
}

static void test_parse_upstreams_invalida(void)
{
    esphole_config_t cfg = {0};
    const char *casos[] = {
        "{\"upstreams\":[\"1.1.1.256\"]}",     /* octeto >255 */
        "{\"upstreams\":[\"1.1.1\"]}",          /* incompleta */
        "{\"upstreams\":[\"noesip\"]}",         /* basura */
        "{\"upstreams\":[\"1.1.1.1.1\"]}",      /* 5 octetos */
        "{\"upstreams\":[\"gggg::1\"]}",        /* v6 inválida */
    };
    for (size_t i = 0; i < sizeof(casos) / sizeof(casos[0]); i++) {
        TEST_ASSERT_EQUAL_INT(WEBAPI_CFG_MALFORMED,
                              webapi_parse_upstreams(casos[i], strlen(casos[i]), &cfg));
    }
}

static void test_parse_upstreams_vacia_y_demasiadas(void)
{
    esphole_config_t cfg = {0};
    const char *vacia = "{\"upstreams\":[]}";
    TEST_ASSERT_EQUAL_INT(WEBAPI_CFG_EMPTY,
                          webapi_parse_upstreams(vacia, strlen(vacia), &cfg));
    const char *muchas =
        "{\"upstreams\":[\"1.1.1.1\",\"2.2.2.2\",\"3.3.3.3\",\"4.4.4.4\",\"5.5.5.5\"]}";
    TEST_ASSERT_EQUAL_INT(WEBAPI_CFG_TOO_MANY,
                          webapi_parse_upstreams(muchas, strlen(muchas), &cfg));
}

static void test_parse_upstreams_no_toca_en_error(void)
{
    esphole_config_t cfg = {0};
    cfg.upstream_count = 42; /* centinela */
    cfg.upstream_addr[0].bytes[0] = 0xEE;
    const char *mala = "{\"upstreams\":[\"basura\"]}";
    TEST_ASSERT_EQUAL_INT(WEBAPI_CFG_MALFORMED,
                          webapi_parse_upstreams(mala, strlen(mala), &cfg));
    TEST_ASSERT_EQUAL_UINT8(42, cfg.upstream_count); /* intacto (FR-007) */
    TEST_ASSERT_EQUAL_UINT8(0xEE, cfg.upstream_addr[0].bytes[0]);
}

static void test_parse_upstreams_fuzz(void)
{
    const char *base = "{\"upstreams\":[\"1.1.1.1\",\"9.9.9.9\"]}";
    char m[64];
    size_t len = strlen(base);
    for (size_t i = 0; i < len; i++) {
        for (int x = 0; x < 3; x++) {
            memcpy(m, base, len + 1);
            m[i] ^= (uint8_t)(1 << x);
            esphole_config_t cfg = {0};
            webapi_cfg_err_t r = webapi_parse_upstreams(m, len, &cfg);
            TEST_ASSERT_TRUE(r == WEBAPI_CFG_OK || r == WEBAPI_CFG_MALFORMED ||
                             r == WEBAPI_CFG_EMPTY || r == WEBAPI_CFG_TOO_MANY);
        }
    }
    for (size_t l = 0; l <= len; l++) {
        esphole_config_t cfg = {0};
        (void)webapi_parse_upstreams(base, l, &cfg);
    }
}

/* --- sesiones (AB-H3) --- */

static void test_session_create_valid(void)
{
    webapi_sessions_t t;
    webapi_sessions_init(&t);
    webapi_session_create(&t, "tok-aaaa", 1000);
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "tok-aaaa", 1000));
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "tok-aaaa", 1000 + WEBAPI_SESSION_TTL_S - 1));
    TEST_ASSERT_FALSE(webapi_session_valid(&t, "otro", 1000));
}

static void test_session_expira(void)
{
    webapi_sessions_t t;
    webapi_sessions_init(&t);
    webapi_session_create(&t, "tok", 1000);
    TEST_ASSERT_FALSE(webapi_session_valid(&t, "tok", 1000 + WEBAPI_SESSION_TTL_S + 1));
}

static void test_session_refresca_al_validar(void)
{
    webapi_sessions_t t;
    webapi_sessions_init(&t);
    webapi_session_create(&t, "tok", 1000);
    /* validar cerca del límite refresca la expiración */
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "tok", 1000 + WEBAPI_SESSION_TTL_S - 10));
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "tok", 1000 + 2 * WEBAPI_SESSION_TTL_S - 20));
}

static void test_session_capacidad_desaloja_mas_antigua(void)
{
    webapi_sessions_t t;
    webapi_sessions_init(&t);
    char tok[8];
    for (int i = 0; i < WEBAPI_SESSIONS; i++) {
        sprintf(tok, "t%d", i);
        webapi_session_create(&t, tok, 1000 + (uint32_t)i);
    }
    /* la 5ª desaloja la más antigua (t0) */
    webapi_session_create(&t, "nueva", 2000);
    TEST_ASSERT_FALSE(webapi_session_valid(&t, "t0", 2000));
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "t1", 2000));
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "nueva", 2000));
}

/* logout: invalidar una sesión concreta sin tocar las demás */
static void test_session_invalidate(void)
{
    webapi_sessions_t t;
    webapi_sessions_init(&t);
    webapi_session_create(&t, "aaa", 1000);
    webapi_session_create(&t, "bbb", 1000);
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "aaa", 1000));

    webapi_session_invalidate(&t, "aaa");
    TEST_ASSERT_FALSE(webapi_session_valid(&t, "aaa", 1000)); /* cerrada */
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "bbb", 1000));  /* las demás intactas */

    /* invalidar un token inexistente es un no-op seguro */
    webapi_session_invalidate(&t, "zzz");
    webapi_session_invalidate(&t, NULL);
    TEST_ASSERT_TRUE(webapi_session_valid(&t, "bbb", 1000));
}

/* --- nonces (AB-H4) --- */

static void test_nonce_un_solo_uso(void)
{
    webapi_nonces_t t;
    webapi_nonces_init(&t);
    webapi_nonce_issue(&t, "n1", 1000);
    TEST_ASSERT_TRUE(webapi_nonce_take(&t, "n1", 1000));
    TEST_ASSERT_FALSE(webapi_nonce_take(&t, "n1", 1000)); /* segundo uso falla */
}

static void test_nonce_desconocido_y_expira(void)
{
    webapi_nonces_t t;
    webapi_nonces_init(&t);
    TEST_ASSERT_FALSE(webapi_nonce_take(&t, "fantasma", 1000));
    webapi_nonce_issue(&t, "n2", 1000);
    TEST_ASSERT_FALSE(webapi_nonce_take(&t, "n2", 1000 + WEBAPI_NONCE_TTL_S + 1));
}

static void test_nonce_tabla_llena_desaloja(void)
{
    webapi_nonces_t t;
    webapi_nonces_init(&t);
    char n[8];
    for (int i = 0; i < WEBAPI_NONCES; i++) {
        sprintf(n, "n%d", i);
        webapi_nonce_issue(&t, n, 1000 + (uint32_t)i);
    }
    webapi_nonce_issue(&t, "extra", 2000); /* desaloja el más antiguo (n0) */
    TEST_ASSERT_FALSE(webapi_nonce_take(&t, "n0", 2000));
    TEST_ASSERT_TRUE(webapi_nonce_take(&t, "extra", 2000));
}

/* --- desafío-respuesta (AB-H5) --- */

/* HMAC-SHA256 de referencia para el test (implementación mínima autónoma) */
#include "sha256_ref.h"

static void ref_hmac(const uint8_t *key, size_t kl, const uint8_t *msg,
                     size_t ml, uint8_t out[32])
{
    hmac_sha256_ref(key, kl, msg, ml, out);
}

static void hex_of(const uint8_t *b, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = H[b[i] >> 4];
        out[i * 2 + 1] = H[b[i] & 0xF];
    }
    out[n * 2] = '\0';
}

static void test_verify_challenge_ok(void)
{
    uint8_t h[32];
    for (int i = 0; i < 32; i++) h[i] = (uint8_t)(i * 7 + 1); /* hash admin fijo */
    const char *nonce = "abc123nonce";
    uint8_t mac[32];
    ref_hmac(h, 32, (const uint8_t *)nonce, strlen(nonce), mac);
    char resp[65];
    hex_of(mac, 32, resp);

    TEST_ASSERT_TRUE(webapi_verify_challenge(h, nonce, resp, ref_hmac));
}

static void test_verify_challenge_resp_o_nonce_alterados(void)
{
    uint8_t h[32];
    for (int i = 0; i < 32; i++) h[i] = (uint8_t)(i * 7 + 1);
    const char *nonce = "abc123nonce";
    uint8_t mac[32];
    ref_hmac(h, 32, (const uint8_t *)nonce, strlen(nonce), mac);
    char resp[65];
    hex_of(mac, 32, resp);

    /* respuesta alterada */
    char mala = resp[0];
    resp[0] = (resp[0] == 'a') ? 'b' : 'a';
    TEST_ASSERT_FALSE(webapi_verify_challenge(h, nonce, resp, ref_hmac));
    resp[0] = mala;
    /* nonce alterado (resp ya no corresponde) */
    TEST_ASSERT_FALSE(webapi_verify_challenge(h, "otro_nonce", resp, ref_hmac));
}

static void test_verify_challenge_longitud_incorrecta(void)
{
    uint8_t h[32] = {0};
    /* resp demasiado corta: rechazada sin leer fuera de rango */
    TEST_ASSERT_FALSE(webapi_verify_challenge(h, "n", "abcd", ref_hmac));
    TEST_ASSERT_FALSE(webapi_verify_challenge(h, "n", "", ref_hmac));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_status_json_campos);
    RUN_TEST(test_status_json_buffer_corto);
    RUN_TEST(test_config_json_upstreams);
    RUN_TEST(test_config_json_v6);
    RUN_TEST(test_parse_upstreams_v4);
    RUN_TEST(test_parse_upstreams_v6);
    RUN_TEST(test_parse_upstreams_invalida);
    RUN_TEST(test_parse_upstreams_vacia_y_demasiadas);
    RUN_TEST(test_parse_upstreams_no_toca_en_error);
    RUN_TEST(test_parse_upstreams_fuzz);
    RUN_TEST(test_session_create_valid);
    RUN_TEST(test_session_expira);
    RUN_TEST(test_session_refresca_al_validar);
    RUN_TEST(test_session_capacidad_desaloja_mas_antigua);
    RUN_TEST(test_session_invalidate);
    RUN_TEST(test_nonce_un_solo_uso);
    RUN_TEST(test_nonce_desconocido_y_expira);
    RUN_TEST(test_nonce_tabla_llena_desaloja);
    RUN_TEST(test_verify_challenge_ok);
    RUN_TEST(test_verify_challenge_resp_o_nonce_alterados);
    RUN_TEST(test_verify_challenge_longitud_incorrecta);
    return UNITY_END();
}
