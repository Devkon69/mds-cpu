/* SPDX-License-Identifier: GPL-3.0-or-later */
/* walk_b3.h - the BLAKE3 pieces of Midstate Walk v1 (single-chunk derive_key XOF), scalar.
 * Seed, re-mix and final hash cost ~140 compressions per attempt against 2^18 steps: <1 %. */
#ifndef WALK_B3_H
#define WALK_B3_H
#include <stdint.h>
#include <string.h>

static const uint32_t WB3_IV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                                   0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
static const uint8_t WB3_SCHED[7][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8},
    {3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1},  {10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6},
    {12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4},  {9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7},
    {11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13}};
#define WB3_F_START 1u
#define WB3_F_END   2u
#define WB3_F_ROOT  8u
#define WB3_F_CTX   32u
#define WB3_F_DKM   64u
#define WB3_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define WB3_G(a, b, c, d, x, y) do { \
    v[a] = v[a] + v[b] + (x); v[d] = WB3_ROTR(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];       v[b] = WB3_ROTR(v[b] ^ v[c], 12); \
    v[a] = v[a] + v[b] + (y); v[d] = WB3_ROTR(v[d] ^ v[a], 8);  \
    v[c] = v[c] + v[d];       v[b] = WB3_ROTR(v[b] ^ v[c], 7); } while (0)

static inline uint32_t wb3_le32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* out[0..15]: the full 16-word output of one compression of blk (message words, little-endian) */
static inline void wb3_compress(const uint32_t cv[8], const uint32_t m[16], uint32_t ctr, uint32_t len, uint32_t flags, uint32_t out[16])
{
    uint32_t v[16] = { cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
                       WB3_IV[0], WB3_IV[1], WB3_IV[2], WB3_IV[3], ctr, 0, len, flags };
    for (int r = 0; r < 7; r++) {
        const uint8_t *s = WB3_SCHED[r];
        WB3_G(0, 4, 8, 12, m[s[0]], m[s[1]]);  WB3_G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        WB3_G(2, 6, 10, 14, m[s[4]], m[s[5]]); WB3_G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        WB3_G(0, 5, 10, 15, m[s[8]], m[s[9]]); WB3_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        WB3_G(2, 7, 8, 13, m[s[12]], m[s[13]]); WB3_G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) { out[i] = v[i] ^ v[i + 8]; out[i + 8] = v[i + 8] ^ cv[i]; }
}

/* derive_key context keys of "midstate walk v1 init / remix / final" */
static uint32_t WB3_KEY[3][8];
static void wb3_init_keys(void)
{
    static const char *ctx[3] = { "midstate walk v1 init", "midstate walk v1 remix", "midstate walk v1 final" };
    for (int k = 0; k < 3; k++) {
        uint8_t blk[64] = {0}; uint32_t m[16], o[16];
        size_t n = strlen(ctx[k]); memcpy(blk, ctx[k], n);
        for (int i = 0; i < 16; i++) m[i] = wb3_le32(blk + 4 * i);
        wb3_compress(WB3_IV, m, 0, (uint32_t)n, WB3_F_START | WB3_F_END | WB3_F_ROOT | WB3_F_CTX, o);
        memcpy(WB3_KEY[k], o, 32);
    }
}

/* XOF output block t (64 bytes as 16 words) of derive_key(key) over a single block of len bytes */
static inline void wb3_xof_block(const uint32_t key[8], const uint32_t m[16], uint32_t len, uint32_t t, uint32_t out[16])
{
    wb3_compress(key, m, t, len, WB3_F_START | WB3_F_END | WB3_F_ROOT | WB3_F_DKM, out);
}
#endif
