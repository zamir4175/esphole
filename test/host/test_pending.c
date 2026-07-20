/*
 * T019 — tests de la tabla de pendientes: dedupe, fan-out, anti-poisoning,
 * desbordes fail-open y timeout con reintento (R5; CB-21/23/26/44/55 unitarios).
 * Reloj y aleatoriedad inyectados.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "dns_wire.h"
#include "pending.h"
#include "wire_helpers.h"

void setUp(void) {}
void tearDown(void) {}

static pending_table_t t;
static uint8_t *mem;

/* rand16 falso determinista */
static uint16_t rand_seq_val;
static uint16_t rand_seq(void) { return rand_seq_val++; }
static uint16_t rand_const(void) { return 0x4242; }

static void init_tabla(uint16_t (*r)(void))
{
    free(mem);
    mem = malloc(pending_mem_size());
    TEST_ASSERT_NOT_NULL(mem);
    TEST_ASSERT_TRUE(pending_mem_size() > 0);
    pending_init(&t, mem, r);
}

/* consulta parseada con cliente sintético */
static dns_query_t consulta_de(const char *name, uint16_t id, uint8_t last_octet)
{
    static pkt_t bufs[80];
    static unsigned bi;
    pkt_t *p = &bufs[bi++ % 80];
    *p = consulta(name, DNS_TYPE_A);
    p->b[0] = (uint8_t)(id >> 8);
    p->b[1] = (uint8_t)(id & 0xFF);
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(p->b, p->len, &q));
    q.client_addr.family = ESPHOLE_AF_V4;
    q.client_addr.bytes[0] = 192;
    q.client_addr.bytes[3] = last_octet;
    q.client_port = (uint16_t)(40000 + last_octet);
    return q;
}

/* respuesta upstream coherente con la consulta (mismo nombre) */
static pkt_t respuesta_para(const char *name, uint16_t txid)
{
    static const uint8_t ip[4] = {1, 2, 3, 4};
    pkt_t p = {.len = 0};
    pheader(&p, txid, 0x8180, 1, 1, 0, 0);
    pname(&p, name);
    p16(&p, DNS_TYPE_A);
    p16(&p, DNS_CLASS_IN);
    precord(&p, DNS_TYPE_A, 300, ip, 4);
    return p;
}

/* --- registro y dedupe --- */

static void test_primera_consulta_es_send(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    dns_query_t q = consulta_de("example.com", 0xAAAA, 10);
    uint16_t txid = 0;
    TEST_ASSERT_EQUAL_INT(PENDING_SEND, pending_register(&t, &q, 0, 1000, &txid));
    TEST_ASSERT_EQUAL_HEX16(0x1000, txid); /* del rand inyectado */
}

static void test_misma_clave_se_agrupa(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    dns_query_t q1 = consulta_de("example.com", 0xAAAA, 10);
    dns_query_t q2 = consulta_de("example.com", 0xBBBB, 20);
    dns_query_t q3 = consulta_de("otro.com", 0xCCCC, 30);
    uint16_t txid = 0;
    TEST_ASSERT_EQUAL_INT(PENDING_SEND, pending_register(&t, &q1, 0, 1000, &txid));
    TEST_ASSERT_EQUAL_INT(PENDING_GROUPED, pending_register(&t, &q2, 0, 1001, &txid));
    TEST_ASSERT_EQUAL_INT(PENDING_SEND, pending_register(&t, &q3, 0, 1002, &txid));
}

/* --- match y fan-out (CB-55) --- */

static void test_match_entrega_todos_los_waiters_y_libera(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    dns_query_t q1 = consulta_de("example.com", 0xAAAA, 10);
    dns_query_t q2 = consulta_de("example.com", 0xBBBB, 20);
    uint16_t txid = 0;
    pending_register(&t, &q1, 0, 1000, &txid);
    pending_register(&t, &q2, 0, 1001, &txid);

    /* el llamador HW valida el origen con el índice de upstream de la entrada */
    uint8_t uidx = 99;
    TEST_ASSERT_TRUE(pending_upstream_of(&t, 0x1000, &uidx));
    TEST_ASSERT_EQUAL_UINT8(0, uidx);
    TEST_ASSERT_FALSE(pending_upstream_of(&t, 0xDEAD, &uidx));

    pkt_t r = respuesta_para("example.com", 0x1000);
    const pending_waiters_t *w = pending_match(&t, 0x1000, r.b, r.len);
    TEST_ASSERT_NOT_NULL(w);
    TEST_ASSERT_EQUAL_UINT8(2, w->count);
    /* la entrega incluye la clave y el instante de envío */
    TEST_ASSERT_EQUAL_STRING("example.com", w->qname);
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_A, w->qtype);
    TEST_ASSERT_EQUAL_UINT32(1000, w->enviado_en);
    TEST_ASSERT_EQUAL_HEX16(0xAAAA, w->w[0].id_original);
    TEST_ASSERT_EQUAL_HEX16(0xBBBB, w->w[1].id_original);
    TEST_ASSERT_EQUAL_UINT8(10, w->w[0].addr.bytes[3]);
    TEST_ASSERT_EQUAL_UINT16(40020, w->w[1].port);

    /* la entrada quedó libre: la misma clave vuelve a ser SEND */
    dns_query_t q3 = consulta_de("example.com", 0xDDDD, 30);
    TEST_ASSERT_EQUAL_INT(PENDING_SEND, pending_register(&t, &q3, 0, 1002, &txid));
}

/* --- anti-poisoning (CB-44) --- */

static void test_txid_desconocido_no_casa(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    dns_query_t q = consulta_de("example.com", 0xAAAA, 10);
    uint16_t txid = 0;
    pending_register(&t, &q, 0, 1000, &txid);

    pkt_t r = respuesta_para("example.com", 0xDEAD);
    TEST_ASSERT_NULL(pending_match(&t, 0xDEAD, r.b, r.len));
}

static void test_txid_correcto_pero_pregunta_distinta_no_casa(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    dns_query_t q = consulta_de("example.com", 0xAAAA, 10);
    uint16_t txid = 0;
    pending_register(&t, &q, 0, 1000, &txid);

    /* un atacante acierta el txid pero responde por otro nombre */
    pkt_t mala = respuesta_para("atacante.com", txid);
    TEST_ASSERT_NULL(pending_match(&t, txid, mala.b, mala.len));

    /* la entrada sigue viva: la respuesta legítima aún casa */
    pkt_t buena = respuesta_para("example.com", txid);
    TEST_ASSERT_NOT_NULL(pending_match(&t, txid, buena.b, buena.len));
}

static void test_txids_unicos_aunque_rand_colisione(void)
{
    init_tabla(rand_const); /* rand siempre 0x4242 */
    dns_query_t q1 = consulta_de("uno.com", 1, 10);
    dns_query_t q2 = consulta_de("dos.com", 2, 20);
    uint16_t t1 = 0, t2 = 0;
    TEST_ASSERT_EQUAL_INT(PENDING_SEND, pending_register(&t, &q1, 0, 1000, &t1));
    TEST_ASSERT_EQUAL_INT(PENDING_SEND, pending_register(&t, &q2, 0, 1001, &t2));
    TEST_ASSERT_NOT_EQUAL(t1, t2);
}

/* --- desbordes fail-open (R5 / CB-26) --- */

static void test_waiters_llenos_envia_sin_agrupar(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    uint16_t txid0 = 0;
    dns_query_t q0 = consulta_de("example.com", 0, 100);
    pending_register(&t, &q0, 0, 1000, &txid0);
    for (int i = 1; i < PENDING_WAITERS; i++) {
        uint16_t tx = 0;
        dns_query_t q = consulta_de("example.com", (uint16_t)i, (uint8_t)(100 + i));
        TEST_ASSERT_EQUAL_INT(PENDING_GROUPED, pending_register(&t, &q, 0, 1000, &tx));
    }
    /* noveno: no cabe como waiter ⇒ entrada propia */
    uint16_t txs = 0;
    dns_query_t q9 = consulta_de("example.com", 99, 200);
    TEST_ASSERT_EQUAL_INT(PENDING_SEND_SOLO, pending_register(&t, &q9, 0, 1001, &txs));
    TEST_ASSERT_NOT_EQUAL(txid0, txs);

    /* el grupo entrega 8; la solitaria entrega 1 */
    pkt_t r = respuesta_para("example.com", txid0);
    const pending_waiters_t *w = pending_match(&t, txid0, r.b, r.len);
    TEST_ASSERT_NOT_NULL(w);
    TEST_ASSERT_EQUAL_UINT8(PENDING_WAITERS, w->count);
    pkt_t rs = respuesta_para("example.com", txs);
    w = pending_match(&t, txs, rs.b, rs.len);
    TEST_ASSERT_NOT_NULL(w);
    TEST_ASSERT_EQUAL_UINT8(1, w->count);
}

static void test_tabla_llena_desaloja_la_mas_antigua(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    char nombre[32];
    uint16_t txid_viejo = 0;
    for (int i = 0; i < PENDING_ENTRIES; i++) {
        snprintf(nombre, sizeof(nombre), "dom%02d.com", i);
        uint16_t tx = 0;
        dns_query_t q = consulta_de(nombre, (uint16_t)i, 10);
        TEST_ASSERT_EQUAL_INT(PENDING_SEND,
                              pending_register(&t, &q, 0, 1000 + (uint32_t)i, &tx));
        if (i == 0) {
            txid_viejo = tx;
        }
    }
    /* tabla llena: la 65ª desaloja a dom00 (la más antigua) y SE ENVÍA */
    uint16_t tx65 = 0;
    dns_query_t q65 = consulta_de("nuevo.com", 65, 10);
    TEST_ASSERT_EQUAL_INT(PENDING_SEND_SOLO,
                          pending_register(&t, &q65, 0, 2000, &tx65));

    pkt_t r0 = respuesta_para("dom00.com", txid_viejo);
    TEST_ASSERT_NULL(pending_match(&t, txid_viejo, r0.b, r0.len)); /* desalojada */
    pkt_t r65 = respuesta_para("nuevo.com", tx65);
    TEST_ASSERT_NOT_NULL(pending_match(&t, tx65, r65.b, r65.len));
}

/* --- timeout: reintento y luego SERVFAIL (CB-21/23) --- */

static void test_expire_reintenta_y_luego_falla(void)
{
    init_tabla(rand_seq);
    rand_seq_val = 0x1000;
    uint16_t txid = 0;
    dns_query_t q = consulta_de("example.com", 0xAAAA, 10);
    pending_register(&t, &q, 0, 1000, &txid);

    pending_action_t acts[4];
    /* antes del timeout: nada */
    TEST_ASSERT_EQUAL_size_t(0, pending_expire(&t, 2000, 1500, acts, 4));

    /* primer vencimiento ⇒ RETRY con txid nuevo hacia el siguiente upstream */
    size_t n = pending_expire(&t, 2600, 1500, acts, 4);
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_INT(PENDING_ACT_RETRY, acts[0].kind);
    TEST_ASSERT_EQUAL_UINT8(1, acts[0].upstream_idx);
    TEST_ASSERT_EQUAL_STRING("example.com", acts[0].qname);
    uint16_t txid2 = acts[0].new_txid;
    TEST_ASSERT_NOT_EQUAL(txid, txid2);

    /* el txid viejo ya no casa; el nuevo sí sigue vivo */
    pkt_t rv = respuesta_para("example.com", txid);
    TEST_ASSERT_NULL(pending_match(&t, txid, rv.b, rv.len));

    /* segundo vencimiento ⇒ FAIL con los waiters, entrada liberada */
    n = pending_expire(&t, 4200, 1500, acts, 4);
    TEST_ASSERT_EQUAL_size_t(1, n);
    TEST_ASSERT_EQUAL_INT(PENDING_ACT_FAIL, acts[0].kind);
    TEST_ASSERT_EQUAL_UINT8(1, acts[0].waiters.count);
    TEST_ASSERT_EQUAL_HEX16(0xAAAA, acts[0].waiters.w[0].id_original);

    pkt_t rn = respuesta_para("example.com", txid2);
    TEST_ASSERT_NULL(pending_match(&t, txid2, rn.b, rn.len));
}

/* --- dns_wire_build_query (para el envío y los reintentos) --- */

static void test_build_query_valida(void)
{
    uint8_t buf[512];
    size_t n = dns_wire_build_query("example.com", 11, DNS_TYPE_A, DNS_CLASS_IN,
                                    0xBEEF, true, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    /* debe ser parseable por nuestro propio parser */
    dns_query_t q;
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(buf, n, &q));
    TEST_ASSERT_EQUAL_HEX16(0xBEEF, q.id);
    TEST_ASSERT_EQUAL_STRING("example.com", q.qname);
    TEST_ASSERT_EQUAL_UINT16(DNS_TYPE_A, q.qtype);
    TEST_ASSERT_TRUE(q.flags & 0x0100); /* RD=1 */
    TEST_ASSERT_TRUE(q.edns_present);
    TEST_ASSERT_EQUAL_UINT16(DNS_WIRE_OUR_EDNS_PAYLOAD, q.edns_payload);

    /* sin EDNS */
    n = dns_wire_build_query("example.com", 11, DNS_TYPE_A, DNS_CLASS_IN, 1,
                             false, buf, sizeof(buf));
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_EQUAL_INT(DNS_WIRE_OK, dns_wire_parse_query(buf, n, &q));
    TEST_ASSERT_FALSE(q.edns_present);
}

static void test_build_query_invalida_o_sin_sitio(void)
{
    uint8_t buf[512];
    TEST_ASSERT_EQUAL_size_t(0, dns_wire_build_query("", 0, DNS_TYPE_A, 1, 1,
                                                     false, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_size_t(0, dns_wire_build_query("a..b", 4, DNS_TYPE_A, 1, 1,
                                                     false, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_size_t(0, dns_wire_build_query("example.com", 11,
                                                     DNS_TYPE_A, 1, 1, false,
                                                     buf, 10));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_primera_consulta_es_send);
    RUN_TEST(test_misma_clave_se_agrupa);
    RUN_TEST(test_match_entrega_todos_los_waiters_y_libera);
    RUN_TEST(test_txid_desconocido_no_casa);
    RUN_TEST(test_txid_correcto_pero_pregunta_distinta_no_casa);
    RUN_TEST(test_txids_unicos_aunque_rand_colisione);
    RUN_TEST(test_waiters_llenos_envia_sin_agrupar);
    RUN_TEST(test_tabla_llena_desaloja_la_mas_antigua);
    RUN_TEST(test_expire_reintenta_y_luego_falla);
    RUN_TEST(test_build_query_valida);
    RUN_TEST(test_build_query_invalida_o_sin_sitio);
    return UNITY_END();
}
