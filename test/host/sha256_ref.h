/*
 * SHA-256 y HMAC-SHA256 de referencia, solo para tests de host (verificar el
 * flujo de webapi_verify_challenge sin depender de mbedTLS). Implementación
 * compacta de dominio público (FIPS 180-4 / RFC 2104). No para producción.
 */
#ifndef SHA256_REF_H
#define SHA256_REF_H

#include <stdint.h>
#include <string.h>

static inline uint32_t sr_ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static inline void sha256_ref(const uint8_t *data, size_t len, uint8_t out[32])
{
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    /* padding: mensaje + 0x80 + ceros + longitud en bits (64-bit BE) */
    uint64_t bitlen = (uint64_t)len * 8;
    size_t total = len + 1;
    while (total % 64 != 56) total++;
    total += 8;
    uint8_t buf[256 + 128]; /* suficiente para los mensajes cortos del test */
    memset(buf, 0, total);
    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) {
        buf[total - 1 - i] = (uint8_t)(bitlen >> (8 * i));
    }
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)buf[off + i * 4] << 24) |
                   ((uint32_t)buf[off + i * 4 + 1] << 16) |
                   ((uint32_t)buf[off + i * 4 + 2] << 8) |
                   ((uint32_t)buf[off + i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = sr_ror(w[i - 15], 7) ^ sr_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = sr_ror(w[i - 2], 17) ^ sr_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = sr_ror(e, 6) ^ sr_ror(e, 11) ^ sr_ror(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = sr_ror(a, 2) ^ sr_ror(a, 13) ^ sr_ror(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
}

static inline void hmac_sha256_ref(const uint8_t *key, size_t kl,
                                   const uint8_t *msg, size_t ml, uint8_t out[32])
{
    uint8_t k[64] = {0};
    if (kl > 64) {
        sha256_ref(key, kl, k); /* clave larga → su hash */
    } else {
        memcpy(k, key, kl);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    uint8_t inner_in[64 + 128];
    memcpy(inner_in, ipad, 64);
    memcpy(inner_in + 64, msg, ml);
    uint8_t inner[32];
    sha256_ref(inner_in, 64 + ml, inner);
    uint8_t outer_in[64 + 32];
    memcpy(outer_in, opad, 64);
    memcpy(outer_in + 64, inner, 32);
    sha256_ref(outer_in, 96, out);
}

#endif /* SHA256_REF_H */
