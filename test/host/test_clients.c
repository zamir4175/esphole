/*
 * Tests host de clients (spec 008, contrato clients-table.md CL-01..08).
 * Tabla fija por IP con desalojo LRU; reloj inyectado. ASan/UBSan.
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "clients.h"

void setUp(void) {}
void tearDown(void) {}

static clients_t C;

/* IPv4 a.b.c.d */
static ip_addr16_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    ip_addr16_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.family = ESPHOLE_AF_V4;
    ip.bytes[0] = a;
    ip.bytes[1] = b;
    ip.bytes[2] = c;
    ip.bytes[3] = d;
    return ip;
}

/* busca la entrada de 'ip' en una instantánea; NULL si no está */
static const client_ent_t *find(const client_ent_t *snap, size_t n,
                                const ip_addr16_t *ip)
{
    for (size_t i = 0; i < n; i++) {
        if (snap[i].ip.family == ip->family &&
            memcmp(snap[i].ip.bytes, ip->bytes, 16) == 0) {
            return &snap[i];
        }
    }
    return NULL;
}

/* CL-01: IP nuevo (no bloqueada) → total=1, blocked=0, visto_s=now */
static void test_nuevo(void)
{
    clients_init(&C);
    ip_addr16_t ip = v4(192, 168, 1, 23);
    clients_record(&C, &ip, false, 100);
    client_ent_t snap[CLIENTS_TABLE];
    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_EQUAL_UINT(1, n);
    const client_ent_t *e = find(snap, n, &ip);
    TEST_ASSERT_NOT_NULL(e);
    TEST_ASSERT_EQUAL_UINT32(1, e->total);
    TEST_ASSERT_EQUAL_UINT32(0, e->blocked);
    TEST_ASSERT_EQUAL_UINT32(100, e->visto_s);
}

/* CL-02: mismo IP otra vez → total=2, visto_s actualizado */
static void test_repite(void)
{
    clients_init(&C);
    ip_addr16_t ip = v4(192, 168, 1, 23);
    clients_record(&C, &ip, false, 100);
    clients_record(&C, &ip, false, 150);
    client_ent_t snap[CLIENTS_TABLE];
    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_EQUAL_UINT(1, n);
    const client_ent_t *e = find(snap, n, &ip);
    TEST_ASSERT_EQUAL_UINT32(2, e->total);
    TEST_ASSERT_EQUAL_UINT32(0, e->blocked);
    TEST_ASSERT_EQUAL_UINT32(150, e->visto_s);
}

/* CL-03: blocked incrementa junto con total */
static void test_blocked(void)
{
    clients_init(&C);
    ip_addr16_t ip = v4(192, 168, 1, 23);
    clients_record(&C, &ip, false, 100);
    clients_record(&C, &ip, true, 101);
    clients_record(&C, &ip, true, 102);
    client_ent_t snap[CLIENTS_TABLE];
    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    const client_ent_t *e = find(snap, n, &ip);
    TEST_ASSERT_EQUAL_UINT32(3, e->total);
    TEST_ASSERT_EQUAL_UINT32(2, e->blocked);
}

/* CL-04: varios IPs → entradas independientes */
static void test_varios(void)
{
    clients_init(&C);
    ip_addr16_t a = v4(192, 168, 1, 10);
    ip_addr16_t b = v4(192, 168, 1, 20);
    clients_record(&C, &a, false, 100);
    clients_record(&C, &a, false, 101);
    clients_record(&C, &b, true, 102);
    client_ent_t snap[CLIENTS_TABLE];
    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_EQUAL_UINT(2, n);
    TEST_ASSERT_EQUAL_UINT32(2, find(snap, n, &a)->total);
    TEST_ASSERT_EQUAL_UINT32(0, find(snap, n, &a)->blocked);
    TEST_ASSERT_EQUAL_UINT32(1, find(snap, n, &b)->total);
    TEST_ASSERT_EQUAL_UINT32(1, find(snap, n, &b)->blocked);
}

/* CL-05: llenar 64 y añadir el 65 (más reciente) → desaloja el visto_s mínimo */
static void test_lru(void)
{
    clients_init(&C);
    /* 64 IPs con visto_s creciente: la 1ª (.1, visto_s=1000) es la más vieja */
    for (int i = 0; i < CLIENTS_TABLE; i++) {
        ip_addr16_t ip = v4(10, 0, (uint8_t)(i >> 8), (uint8_t)i);
        clients_record(&C, &ip, false, (uint32_t)(1000 + i));
    }
    client_ent_t snap[CLIENTS_TABLE];
    TEST_ASSERT_EQUAL_UINT(CLIENTS_TABLE, clients_snapshot(&C, snap, CLIENTS_TABLE));

    ip_addr16_t vieja = v4(10, 0, 0, 0);   /* visto_s=1000, la más antigua */
    ip_addr16_t nueva = v4(172, 16, 0, 99); /* nueva, más reciente */
    clients_record(&C, &nueva, false, 5000);

    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_EQUAL_UINT(CLIENTS_TABLE, n); /* sigue llena, no crece */
    TEST_ASSERT_NOT_NULL(find(snap, n, &nueva)); /* el nuevo entró */
    TEST_ASSERT_NULL(find(snap, n, &vieja));     /* la más vieja se fue */
    /* una que no era la más vieja sigue */
    ip_addr16_t otra = v4(10, 0, 0, 5);
    TEST_ASSERT_NOT_NULL(find(snap, n, &otra));
}

/* CL-06: snapshot con cap < nº en uso → copia exactamente cap, sin desbordar */
static void test_snapshot_cap(void)
{
    clients_init(&C);
    for (int i = 0; i < 10; i++) {
        ip_addr16_t ip = v4(10, 0, 0, (uint8_t)i);
        clients_record(&C, &ip, false, (uint32_t)(100 + i));
    }
    client_ent_t snap[4];
    size_t n = clients_snapshot(&C, snap, 4);
    TEST_ASSERT_EQUAL_UINT(4, n); /* acotado a cap */
}

/* CL-07: reset → tabla vacía */
static void test_reset(void)
{
    clients_init(&C);
    ip_addr16_t ip = v4(192, 168, 1, 23);
    clients_record(&C, &ip, false, 100);
    clients_record(&C, &ip, true, 101);
    clients_reset(&C);
    client_ent_t snap[CLIENTS_TABLE];
    TEST_ASSERT_EQUAL_UINT(0, clients_snapshot(&C, snap, CLIENTS_TABLE));
    /* tras reiniciar, un IP reaparece desde cero */
    clients_record(&C, &ip, false, 200);
    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_EQUAL_UINT(1, n);
    TEST_ASSERT_EQUAL_UINT32(1, find(snap, n, &ip)->total);
}

/* CL-08: v4 vs v6 con bytes bajos iguales → entradas distintas; + mini-fuzz */
static void test_v4_v6_y_fuzz(void)
{
    clients_init(&C);
    ip_addr16_t a4 = v4(1, 2, 3, 4);
    ip_addr16_t a6;
    memset(&a6, 0, sizeof(a6));
    a6.family = ESPHOLE_AF_V6;
    a6.bytes[0] = 1;
    a6.bytes[1] = 2;
    a6.bytes[2] = 3;
    a6.bytes[3] = 4; /* mismos bytes bajos que a4, pero v6 */
    clients_record(&C, &a4, false, 100);
    clients_record(&C, &a6, false, 101);
    client_ent_t snap[CLIENTS_TABLE];
    size_t n = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_EQUAL_UINT(2, n); /* v4 y v6 son distintas */

    /* mini-fuzz: muchas IPs pseudoaleatorias; nunca desborda ni lee fuera */
    clients_init(&C);
    uint32_t x = 0x1234;
    for (int i = 0; i < 5000; i++) {
        x = x * 1103515245u + 12345u;
        ip_addr16_t ip = v4((uint8_t)(x >> 24), (uint8_t)(x >> 16),
                            (uint8_t)(x >> 8), (uint8_t)x);
        clients_record(&C, &ip, (x & 1) != 0, 1000 + (uint32_t)i);
    }
    size_t m = clients_snapshot(&C, snap, CLIENTS_TABLE);
    TEST_ASSERT_TRUE(m <= CLIENTS_TABLE);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_nuevo);
    RUN_TEST(test_repite);
    RUN_TEST(test_blocked);
    RUN_TEST(test_varios);
    RUN_TEST(test_lru);
    RUN_TEST(test_snapshot_cap);
    RUN_TEST(test_reset);
    RUN_TEST(test_v4_v6_y_fuzz);
    return UNITY_END();
}
