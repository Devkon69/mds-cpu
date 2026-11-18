/* SPDX-License-Identifier: GPL-3.0-or-later */
/* walk.c - see walk.h */
#include <string.h>
#include <stdlib.h>
#include "walk_ref.h"

#define LINES 4096
#define STEPS (1u << 18)
#define REMIX (1u << 12)

/* ---------------------------------------------------------------- BLAKE3 (single chunk) */
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
/* derive_key context keys (BLAKE3 of the context string, DERIVE_KEY_CONTEXT) */
static uint32_t KEYS[3][8];
#define F_START 1
#define F_END   2
#define F_ROOT  8
#define F_CTX   32
#define F_DKM   64
static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }
static void st64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) { p[i] = (uint8_t)v; v >>= 8; } }
static void st32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

/* full 16-word output of one compression */
static void compress(const uint32_t cv[8], const uint8_t blk[64], uint32_t ctr, uint32_t len, uint32_t flags, uint32_t out[16])
{
    uint32_t m[16], v[16];
    for (int i = 0; i < 16; i++) m[i] = le32(blk + 4 * i);
    for (int i = 0; i < 8; i++) v[i] = cv[i];
    v[8] = IV[0]; v[9] = IV[1]; v[10] = IV[2]; v[11] = IV[3];
    v[12] = ctr; v[13] = 0; v[14] = len; v[15] = flags;
    for (int r = 0; r < 7; r++) {
        const uint8_t *s = SCHED[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);  G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) { out[i] = v[i] ^ v[i + 8]; out[i + 8] = v[i + 8] ^ cv[i]; }
}
/* key of a derive_key context string (< 64 bytes) */
static void context_key(const char *ctx, uint32_t key[8])
{
    uint8_t blk[64] = {0}; uint32_t o[16];
    size_t n = strlen(ctx); memcpy(blk, ctx, n);
    compress(IV, blk, 0, (uint32_t)n, F_START | F_END | F_ROOT | F_CTX, o);
    memcpy(key, o, 32);
}
/* derive_key XOF of a single-block input (len <= 64): output block t */
static void dk_block(const uint32_t key[8], const uint8_t *in, unsigned len, uint32_t t, uint8_t out[64])
{
    uint8_t blk[64] = {0}; uint32_t o[16];
    memcpy(blk, in, len);
    compress(key, blk, t, len, F_START | F_END | F_ROOT | F_DKM, o);
    for (int i = 0; i < 16; i++) st32(out + 4 * i, o[i]);
}

/* ---------------------------------------------------------------- AES round (AESENC) */
static uint8_t SB[256]; static int sb_ready;
static uint8_t xt(uint8_t a) { return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0)); }
static void sbox_init(void)
{
    uint8_t p = 1, q = 1;                          /* generator 3 and its inverse walk GF(2^8) */
    do {
        p = p ^ xt(p);                             /* p *= 3 */
        q ^= q << 1; q ^= q << 2; q ^= q << 4;     /* q /= 3 */
        if (q & 0x80) q ^= 0x09;
        uint8_t x = q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6))
                      ^ (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4));
        SB[p] = x ^ 0x63;
    } while (p != 1);
    SB[0] = 0x63; sb_ready = 1;
}
static void aesenc(uint8_t o[16], const uint8_t s[16], const uint8_t k[16])
{
    uint8_t t[16];
    for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) t[4 * c + r] = SB[s[4 * ((c + r) & 3) + r]];
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = t[4*c], a1 = t[4*c+1], a2 = t[4*c+2], a3 = t[4*c+3];
        o[4*c]   = xt(a0) ^ xt(a1) ^ a1 ^ a2 ^ a3 ^ k[4*c];
        o[4*c+1] = a0 ^ xt(a1) ^ xt(a2) ^ a2 ^ a3 ^ k[4*c+1];
        o[4*c+2] = a0 ^ a1 ^ xt(a2) ^ xt(a3) ^ a3 ^ k[4*c+2];
        o[4*c+3] = xt(a0) ^ a0 ^ a1 ^ a2 ^ xt(a3) ^ k[4*c+3];
    }
}

/* ---------------------------------------------------------------- the walk */
static void program(uint64_t z, uint8_t p[8])
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)i;
    for (int i = 7; i >= 1; i--) { uint64_t n = (uint64_t)i + 1; int j = (int)(z % n); uint8_t t = p[i]; p[i] = p[j]; p[j] = t; z /= n; }
}
static uint64_t mulhi(uint64_t a, uint64_t b)
{
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
#else
    uint64_t al = (uint32_t)a, ah = a >> 32, bl = (uint32_t)b, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
#endif
}

void walk_hash(const uint8_t mh[32], uint64_t nonce, uint8_t out[32])
{
    static uint64_t (*pad)[8];
    if (!sb_ready) {
        sbox_init();
        context_key("midstate walk v1 init", KEYS[0]);
        context_key("midstate walk v1 remix", KEYS[1]);
        context_key("midstate walk v1 final", KEYS[2]);
    }
    if (!pad) pad = malloc(sizeof(uint64_t) * 8 * LINES);
    uint8_t in[40], seed[256];
    memcpy(in, mh, 32); st64(in + 32, nonce);
    for (uint32_t t = 0; t < 4; t++) dk_block(KEYS[0], in, 40, t, seed + 64 * t);
    uint64_t r[8]; for (int k = 0; k < 8; k++) r[k] = le64(seed + 8 * k);
    uint8_t prog[8]; program(le64(seed + 192), prog);
    uint8_t S[4][16], K[4][16];
    for (int q = 0; q < 4; q++) { memcpy(S[q], seed + 64 + 16 * q, 16); memcpy(K[q], seed + 128 + 16 * q, 16); }
    for (int n = 0; n < LINES; n++) for (int q = 0; q < 4; q++) {
        uint8_t o[16]; aesenc(o, S[q], K[q]); memcpy(S[q], o, 16);
        pad[n][2 * q] = le64(o); pad[n][2 * q + 1] = le64(o + 8);
    }
    uint64_t c = 0; const uint64_t M = LINES - 1;
    for (uint32_t i = 0; i < STEPS; i++) {
        int s = i & 7; uint64_t x = r[s] ^ c;
        uint32_t a = x & M, t = (s + 1 + ((x >> 12) & 3)) & 7, j = (x >> 14) & 7, e = (x >> 17) & M, b = (x >> 32) & M, f = (x >> 44) & M;
        uint64_t m0 = pad[a][j], m1 = pad[b][j ^ 4], m2 = pad[e][j ^ 2], m3 = pad[f][j ^ 6];
        uint64_t k = r[t], v = x ^ m0 ^ m2, y, hi = 0;
        switch (prog[s]) {
        case 0: y = v * (k | 1); break;
        case 1: y = v ^ mulhi(v, k); break;
        case 2: y = v + k / ((uint64_t)(uint32_t)v | 0x80000001ull); break;
        case 3: { uint8_t st[16], o[16], z[16] = {0}; st64(st, v); st64(st + 8, k); aesenc(o, st, z); y = le64(o); hi = le64(o + 8); } break;
        case 4: { unsigned n = k & 63; y = n ? (v >> n) | (v << (64 - n)) : v; } break;
        case 5: y = v + k; break;
        case 6: y = v - k; break;
        default: y = v ^ k;
        }
        uint64_t o = y ^ m1 ^ m3; r[s] = o; r[t] ^= hi; c = o;
        pad[a][j] = m0 ^ y; pad[b][j ^ 4] = m1 + x; pad[e][j ^ 2] = m2 + y; pad[f][j ^ 6] = m3 ^ x;
        if (((i + 1) & (REMIX - 1)) == 0) {
            uint8_t rb[64], o0[64], o1[64];
            for (int q = 0; q < 8; q++) st64(rb + 8 * q, r[q]);
            dk_block(KEYS[1], rb, 64, 0, o0); dk_block(KEYS[1], rb, 64, 1, o1);
            for (int q = 0; q < 8; q++) r[q] = le64(o0 + 8 * q);
            program(le64(o1), prog);
        }
    }
    /* final: derive_key("midstate walk v1 final", mining_hash || nonce || r) = 104 bytes, two blocks */
    uint8_t fin[128] = {0}; uint32_t o[16], cv[8];
    memcpy(fin, in, 40); for (int q = 0; q < 8; q++) st64(fin + 40 + 8 * q, r[q]);
    compress(KEYS[2], fin, 0, 64, F_START | F_DKM, o); memcpy(cv, o, 32);
    compress(cv, fin + 64, 0, 40, F_END | F_ROOT | F_DKM, o);
    for (int i = 0; i < 8; i++) st32(out + 4 * i, o[i]);
}

int walk_selftest(void)
{
    static const char *G3[3][3] = {
        {"0000000000000000000000000000000000000000000000000000000000000000", "0", "a934fced2d9a53fb09d6abe089f3d2f5bba9a421b41ee5726233a525cc7438e7"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "18446744073709551615", "65d237f595f07bee156c635ad45f721987ce38d79ea14c89e40c5555613d0768"},
        {"374bf98b3b8f7f41a9e291154fc582a65bb3e14180cb9a07fef08e55f3006c50", "42", "5f2da9d320de391aef28bcaab63e3d1a25402b4541cdff8680059a87c7d515b7"}};
    for (int g = 0; g < 3; g++) {
        uint8_t mh[32], want[32], got[32];
        for (int i = 0; i < 32; i++) {
            unsigned v1, v2; char b[3] = { G3[g][0][2*i], G3[g][0][2*i+1], 0 }, w[3] = { G3[g][2][2*i], G3[g][2][2*i+1], 0 };
            v1 = (unsigned)strtoul(b, 0, 16); v2 = (unsigned)strtoul(w, 0, 16); mh[i] = (uint8_t)v1; want[i] = (uint8_t)v2;
        }
        walk_hash(mh, strtoull(G3[g][1], 0, 10), got);
        if (memcmp(got, want, 32)) return 0;
    }
    return 1;
}
