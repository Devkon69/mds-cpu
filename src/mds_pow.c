/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mds_pow.c - see mds_pow.h. Portable C, no dependencies. */
#include <string.h>
#include "mds_pow.h"

static const uint32_t IV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                               0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
static const uint8_t SCHED[7][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8},
    {3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1},  {10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6},
    {12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4},  {9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7},
    {11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13}};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define G(a, b, c, d, x, y) do { \
    v[a] = v[a] + v[b] + (x); v[d] = ROTR(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];       v[b] = ROTR(v[b] ^ v[c], 12); \
    v[a] = v[a] + v[b] + (y); v[d] = ROTR(v[d] ^ v[a], 8);  \
    v[c] = v[c] + v[d];       v[b] = ROTR(v[b] ^ v[c], 7); } while (0)

static void compress(const uint32_t m[16], uint32_t block_len, uint32_t h[8])
{
    uint32_t v[16] = {IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7],
                      IV[0], IV[1], IV[2], IV[3], 0, 0, block_len, 11};
    for (int r = 0; r < 7; r++) {
        const uint8_t *s = SCHED[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);  G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) h[i] = v[i] ^ v[i + 8];
}

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

void mds_blake3_small(const uint8_t *in, unsigned len, uint8_t out[32])
{
    uint8_t blk[64] = {0};
    uint32_t m[16], h[8];
    memcpy(blk, in, len);
    for (int i = 0; i < 16; i++) m[i] = le32(blk + 4 * i);
    compress(m, len, h);
    for (int i = 0; i < 8; i++) { out[4*i] = h[i]; out[4*i+1] = h[i] >> 8; out[4*i+2] = h[i] >> 16; out[4*i+3] = h[i] >> 24; }
}

void mds_extension(const uint8_t midstate[32], uint64_t nonce, uint32_t iters, uint8_t out[32])
{
    uint32_t m[16] = {0}, h[8];
    for (int i = 0; i < 8; i++) m[i] = le32(midstate + 4 * i);
    m[8] = (uint32_t)nonce; m[9] = (uint32_t)(nonce >> 32);
    compress(m, 40, h);
    m[8] = m[9] = 0;
    for (uint32_t k = 0; k < iters; k++) {
        memcpy(m, h, 32);
        compress(m, 32, h);
    }
    for (int i = 0; i < 8; i++) { out[4*i] = h[i]; out[4*i+1] = h[i] >> 8; out[4*i+2] = h[i] >> 16; out[4*i+3] = h[i] >> 24; }
}

int mds_hash_lt(const uint8_t a[32], const uint8_t b[32]) { return memcmp(a, b, 32) < 0; }
