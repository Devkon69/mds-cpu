/* SPDX-License-Identifier: GPL-3.0-or-later */
/* walk_engine.c - Midstate Walk v1 on a CPU: K walks stepped in turn per thread.
 *
 * Compiled once per instruction set:
 *   -DWE_SOFT                          portable (table AES), any x86-64
 *   -DWE_AESNI -maes -msse4.1          AES-NI
 *   -DWE_V3 -march=x86-64-v3 -maes     AES-NI + AVX2/BMI2 code generation (Haswell / Zen and newer)
 * Each build defines walk_k1_<isa> .. walk_k6_<isa>:
 *
 *   int walk_kK_<isa>(const uint8_t mh[32], const uint64_t nonce[K], uint8_t out[K][32],
 *                     uint64_t *pads, volatile const uint32_t *seqp, uint32_t seq);
 *
 * pads = K scratchpads of 4096 x 8 words, 64-byte aligned. Returns 1 when done, 0 if *seqp
 * stopped being seq (checked at every re-mix, i.e. every 4096 steps).
 *
 * Why it is fast: the walk is one dependent chain per attempt (load -> operation -> next
 * address), so a single walk leaves a core mostly waiting on L2. Walks of other nonces are
 * independent: stepping K of them in turn lets the out-of-order core overlap K chains. The
 * eight steps of a round are fully unrolled for every walk, so each (walk, register) has its
 * own operation dispatch, which jumps to the same place for 4096 steps: always predicted. */
#include <stdint.h>
#include <string.h>
#include "walk_b3.h"
#if defined(WE_AESNI) || defined(WE_V3)
#include <immintrin.h>
#endif

#define W_LINES 4096u
#define W_STEPS (1u << 18)
#define W_REMIX (1u << 12)
#define W_MASK  (W_LINES - 1)

#if defined(WE_SOFT)
#define ISA soft
#elif defined(WE_AESNI)
#define ISA aesni
#elif defined(WE_V3)
#define ISA v3
#else
#error "WE_SOFT / WE_AESNI / WE_V3"
#endif
#define CAT3_(a, b, c) a##b##c
#define CAT3(a, b, c) CAT3_(a, b, c)
#define FNAME(k) CAT3(walk_k, k, CAT3(_, ISA, ))

/* ---------------------------------------------------------------- AES round */
#if defined(WE_SOFT)
static uint32_t TE[4][256]; static uint8_t SBX[256]; static int te_ready;
static uint8_t xt8(uint8_t a) { return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0)); }
static void soft_init(void)
{
    if (te_ready) return;
    uint8_t p = 1, q = 1;
    do {
        p = p ^ xt8(p);
        q ^= q << 1; q ^= q << 2; q ^= q << 4;
        if (q & 0x80) q ^= 0x09;
        uint8_t x = q ^ (uint8_t)((q << 1) | (q >> 7)) ^ (uint8_t)((q << 2) | (q >> 6)) ^ (uint8_t)((q << 3) | (q >> 5)) ^ (uint8_t)((q << 4) | (q >> 4));
        SBX[p] = x ^ 0x63;
    } while (p != 1);
    SBX[0] = 0x63;
    for (int i = 0; i < 256; i++) {
        uint8_t s = SBX[i], s2 = xt8(s), s3 = s2 ^ s;
        uint32_t w = (uint32_t)s2 | (uint32_t)s << 8 | (uint32_t)s << 16 | (uint32_t)s3 << 24;   /* column bytes 0..3 */
        for (int r = 0; r < 4; r++) TE[r][i] = (w << (8 * r)) | (w >> (32 - 8 * r));
    }
    te_ready = 1;
}
/* AESENC on the 16-byte state (lo || hi, little-endian), key (klo || khi) */
static inline void aes_soft(uint64_t lo, uint64_t hi, uint64_t klo, uint64_t khi, uint64_t *olo, uint64_t *ohi)
{
    uint8_t s[16]; memcpy(s, &lo, 8); memcpy(s + 8, &hi, 8);
    uint32_t c[4];
    for (int col = 0; col < 4; col++)
        c[col] = TE[0][s[4 * col]] ^ TE[1][s[4 * ((col + 1) & 3) + 1]] ^ TE[2][s[4 * ((col + 2) & 3) + 2]] ^ TE[3][s[4 * ((col + 3) & 3) + 3]];
    *olo = ((uint64_t)c[0] | (uint64_t)c[1] << 32) ^ klo;
    *ohi = ((uint64_t)c[2] | (uint64_t)c[3] << 32) ^ khi;
}
#define AES_OP(v, k, y, h) aes_soft(v, k, 0, 0, &(y), &(h))
#else
#define AES_OP(v, k, y, h) do { \
    __m128i st_ = _mm_aesenc_si128(_mm_set_epi64x((long long)(k), (long long)(v)), _mm_setzero_si128()); \
    (y) = (uint64_t)_mm_cvtsi128_si64(st_); (h) = (uint64_t)_mm_extract_epi64(st_, 1); } while (0)
#endif

/* ---------------------------------------------------------------- seed, pad, re-mix, final */
static inline void program(uint64_t z, uint8_t p[8])
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)i;
    for (int i = 7; i >= 1; i--) { uint64_t n = (uint64_t)i + 1; int j = (int)(z % n); uint8_t t = p[i]; p[i] = p[j]; p[j] = t; z /= n; }
}

static void walk_start(const uint8_t mh[32], uint64_t nonce, uint64_t r[8], uint8_t prog[8], uint64_t *pad)
{
    uint32_t m[16] = {0}, o[4][16];
    for (int i = 0; i < 8; i++) m[i] = wb3_le32(mh + 4 * i);
    m[8] = (uint32_t)nonce; m[9] = (uint32_t)(nonce >> 32);
    for (uint32_t t = 0; t < 4; t++) wb3_xof_block(WB3_KEY[0], m, 40, t, o[t]);
    uint64_t sd[32];   /* the 256 output bytes as words; seed = first 200 bytes */
    for (int t = 0; t < 4; t++) for (int i = 0; i < 8; i++) sd[8 * t + i] = (uint64_t)o[t][2 * i] | (uint64_t)o[t][2 * i + 1] << 32;
    for (int k = 0; k < 8; k++) r[k] = sd[k];
    program(sd[24], prog);
    /* pad: four AES lanes S[q] = seed[64+16q..], keys K[q] = seed[128+16q..] */
#if defined(WE_SOFT)
    soft_init();
    uint64_t sl[4], sh[4];
    for (int q = 0; q < 4; q++) { sl[q] = sd[8 + 2 * q]; sh[q] = sd[9 + 2 * q]; }
    for (uint32_t n = 0; n < W_LINES; n++) {
        uint64_t *line = pad + 8 * n;
        for (int q = 0; q < 4; q++) { aes_soft(sl[q], sh[q], sd[16 + 2 * q], sd[17 + 2 * q], &sl[q], &sh[q]); line[2 * q] = sl[q]; line[2 * q + 1] = sh[q]; }
    }
#else
    __m128i S0 = _mm_loadu_si128((const __m128i *)&sd[8]),  S1 = _mm_loadu_si128((const __m128i *)&sd[10]);
    __m128i S2 = _mm_loadu_si128((const __m128i *)&sd[12]), S3 = _mm_loadu_si128((const __m128i *)&sd[14]);
    __m128i K0 = _mm_loadu_si128((const __m128i *)&sd[16]), K1 = _mm_loadu_si128((const __m128i *)&sd[18]);
    __m128i K2 = _mm_loadu_si128((const __m128i *)&sd[20]), K3 = _mm_loadu_si128((const __m128i *)&sd[22]);
    for (uint32_t n = 0; n < W_LINES; n++) {
        __m128i *line = (__m128i *)(pad + 8 * n);
        S0 = _mm_aesenc_si128(S0, K0); S1 = _mm_aesenc_si128(S1, K1); S2 = _mm_aesenc_si128(S2, K2); S3 = _mm_aesenc_si128(S3, K3);
        _mm_store_si128(line, S0); _mm_store_si128(line + 1, S1); _mm_store_si128(line + 2, S2); _mm_store_si128(line + 3, S3);
    }
#endif
}

static void walk_remix(uint64_t r[8], uint8_t prog[8])
{
    uint32_t m[16], o0[16], o1[16];
    for (int i = 0; i < 8; i++) { m[2 * i] = (uint32_t)r[i]; m[2 * i + 1] = (uint32_t)(r[i] >> 32); }
    wb3_xof_block(WB3_KEY[1], m, 64, 0, o0);
    wb3_xof_block(WB3_KEY[1], m, 64, 1, o1);
    for (int i = 0; i < 8; i++) r[i] = (uint64_t)o0[2 * i] | (uint64_t)o0[2 * i + 1] << 32;
    program((uint64_t)o1[0] | (uint64_t)o1[1] << 32, prog);
}

static void walk_finish(const uint8_t mh[32], uint64_t nonce, const uint64_t r[8], uint8_t out[32])
{
    /* derive_key(final) over mining_hash(32) || nonce(8) || r(64) = 104 bytes: two blocks */
    uint32_t m1[16], m2[16] = {0}, o[16], cv[8];
    for (int i = 0; i < 8; i++) m1[i] = wb3_le32(mh + 4 * i);
    m1[8] = (uint32_t)nonce; m1[9] = (uint32_t)(nonce >> 32);
    for (int i = 0; i < 3; i++) { m1[10 + 2 * i] = (uint32_t)r[i]; m1[11 + 2 * i] = (uint32_t)(r[i] >> 32); }
    for (int i = 3; i < 8; i++) { m2[2 * (i - 3)] = (uint32_t)r[i]; m2[2 * (i - 3) + 1] = (uint32_t)(r[i] >> 32); }
    wb3_compress(WB3_KEY[2], m1, 0, 64, WB3_F_START | WB3_F_DKM, o);
    memcpy(cv, o, 32);
    wb3_compress(cv, m2, 0, 40, WB3_F_END | WB3_F_ROOT | WB3_F_DKM, o);
    memcpy(out, o, 32);
}

/* ---------------------------------------------------------------- one step */
/* walk W, register S (constant): see walk.rs. r[W][t] and the pad words live in memory, the
   chain value c[W] in a register. */
#ifndef WE_AHEAD
#define STEP(W, S) do { \
    uint64_t x_ = r[W][S] ^ c##W; \
    uint64_t *P_ = pad##W; \
    uint32_t j_ = (uint32_t)(x_ >> 14) & 7u; \
    uint64_t *p0_ = P_ + (((uint32_t)x_ & W_MASK) << 3) + j_; \
    uint64_t *p1_ = P_ + (((uint32_t)(x_ >> 32) & W_MASK) << 3) + (j_ ^ 4u); \
    uint64_t *p2_ = P_ + (((uint32_t)(x_ >> 17) & W_MASK) << 3) + (j_ ^ 2u); \
    uint64_t *p3_ = P_ + (((uint32_t)(x_ >> 44) & W_MASK) << 3) + (j_ ^ 6u); \
    uint32_t t_ = (S + 1u + ((uint32_t)(x_ >> 12) & 3u)) & 7u; \
    uint64_t m0_ = *p0_, m1_ = *p1_, m2_ = *p2_, m3_ = *p3_; \
    uint64_t k_ = r[W][t_], v_ = x_ ^ m0_ ^ m2_, y_; \
    OPSWITCH(W, S) \
    uint64_t o_ = y_ ^ m1_ ^ m3_; \
    r[W][S] = o_; c##W = o_; \
    *p0_ = m0_ ^ y_; *p1_ = m1_ + x_; *p2_ = m2_ + y_; *p3_ = m3_ ^ x_; \
} while (0)
#define AES_FIX(W, S)
#else
/* "ahead": the next step's x = r[S+1] ^ m1 ^ m3 ^ y, with everything but y known before the
   operation, so only one XOR follows it on the chain. c##W holds this step's x. */
#define STEP(W, S) do { \
    uint64_t x_ = c##W; \
    uint64_t *P_ = pad##W; \
    uint32_t j_ = (uint32_t)(x_ >> 14) & 7u; \
    uint64_t *p0_ = P_ + (((uint32_t)x_ & W_MASK) << 3) + j_; \
    uint64_t *p1_ = P_ + (((uint32_t)(x_ >> 32) & W_MASK) << 3) + (j_ ^ 4u); \
    uint64_t *p2_ = P_ + (((uint32_t)(x_ >> 17) & W_MASK) << 3) + (j_ ^ 2u); \
    uint64_t *p3_ = P_ + (((uint32_t)(x_ >> 44) & W_MASK) << 3) + (j_ ^ 6u); \
    uint32_t t_ = (S + 1u + ((uint32_t)(x_ >> 12) & 3u)) & 7u; \
    uint64_t m0_ = *p0_, m1_ = *p1_, m2_ = *p2_, m3_ = *p3_; \
    uint64_t k_ = r[W][t_], v_ = x_ ^ m0_ ^ m2_, y_, w13_ = m1_ ^ m3_; \
    uint64_t u_ = r[W][(S + 1) & 7] ^ w13_; \
    OPSWITCH_A(W, S) \
    r[W][S] = y_ ^ w13_; c##W = u_ ^ y_; \
    *p0_ = m0_ ^ y_; *p1_ = m1_ + x_; *p2_ = m2_ + y_; *p3_ = m3_ ^ x_; \
} while (0)
#endif

#ifdef WE_GOTO
/* byte offsets: line a at (x << 6) & 0x3FFC0, e at (x >> 11), b at (x >> 26), f at (x >> 38)
   (same mask); word j as byte (x >> 11) & 0x38 ORed into the 64-byte aligned pad pointer, its
   partners j^4, j^2, j^6 by XOR 32, 16, 48. The operation by a computed goto per (walk,
   register), retargeted at every re-mix. */
#define LBL_(W, S, o) l_##W##_##S##_##o
#define LBL(W, S, o) LBL_(W, S, o)
#define STEPG(W, S) do { \
    uint64_t x_ = c##W; \
    uint64_t x11_ = x_ >> 11; \
    uintptr_t pj_ = (uintptr_t)pad##W | (uintptr_t)(x11_ & 0x38u); \
    uint64_t *p0_ = (uint64_t *)(pj_ + ((x_ << 6) & 0x3FFC0u)); \
    uint64_t *p2_ = (uint64_t *)((pj_ ^ 16u) + (x11_ & 0x3FFC0u)); \
    uint64_t *p1_ = (uint64_t *)((pj_ ^ 32u) + ((x_ >> 26) & 0x3FFC0u)); \
    uint64_t *p3_ = (uint64_t *)((pj_ ^ 48u) + ((x_ >> 38) & 0x3FFC0u)); \
    uint32_t t_ = (S + 1u + ((uint32_t)(x_ >> 12) & 3u)) & 7u; \
    uint64_t m0_ = *p0_, m1_ = *p1_, m2_ = *p2_, m3_ = *p3_; \
    uint64_t k_ = r[W][t_], v_ = x_ ^ m0_ ^ m2_, y_, w13_ = m1_ ^ m3_; \
    uint64_t u_ = r[W][(S + 1) & 7] ^ w13_; \
    goto *jt[W][S]; \
    LBL(W, S, 0): y_ = v_ * (k_ | 1); goto LBL(W, S, d); \
    LBL(W, S, 1): y_ = v_ ^ (uint64_t)(((unsigned __int128)v_ * k_) >> 64); goto LBL(W, S, d); \
    LBL(W, S, 2): y_ = v_ + k_ / ((uint64_t)(uint32_t)v_ | 0x80000001ull); goto LBL(W, S, d); \
    LBL(W, S, 3): { uint64_t h_; AES_OP(v_, k_, y_, h_); r[W][t_] = k_ ^ h_; if (t_ == ((S + 1) & 7)) u_ ^= h_; } goto LBL(W, S, d); \
    LBL(W, S, 4): { unsigned n_ = (unsigned)k_ & 63u; y_ = (v_ >> n_) | (v_ << ((64u - n_) & 63u)); } goto LBL(W, S, d); \
    LBL(W, S, 5): y_ = v_ + k_; goto LBL(W, S, d); \
    LBL(W, S, 6): y_ = v_ - k_; goto LBL(W, S, d); \
    LBL(W, S, 7): y_ = v_ ^ k_; \
    LBL(W, S, d): \
    r[W][S] = y_ ^ w13_; c##W = u_ ^ y_; \
    *p0_ = m0_ ^ y_; *p1_ = m1_ + x_; *p2_ = m2_ + y_; *p3_ = m3_ ^ x_; \
} while (0)
#define TBL(W, S) { &&LBL(W, S, 0), &&LBL(W, S, 1), &&LBL(W, S, 2), &&LBL(W, S, 3), &&LBL(W, S, 4), &&LBL(W, S, 5), &&LBL(W, S, 6), &&LBL(W, S, 7) }
#define TBLW(W) { TBL(W, 0), TBL(W, 1), TBL(W, 2), TBL(W, 3), TBL(W, 4), TBL(W, 5), TBL(W, 6), TBL(W, 7) }
#endif

#ifdef WE_ADDR
#undef STEP
#define STEP(W, S) do { \
    uint64_t x_ = c##W; \
    uint64_t x11_ = x_ >> 11; \
    uintptr_t pj_ = (uintptr_t)pad##W | (uintptr_t)(x11_ & 0x38u); \
    uint64_t *p0_ = (uint64_t *)(pj_ + ((x_ << 6) & 0x3FFC0u)); \
    uint64_t *p2_ = (uint64_t *)((pj_ ^ 16u) + (x11_ & 0x3FFC0u)); \
    uint64_t *p1_ = (uint64_t *)((pj_ ^ 32u) + ((x_ >> 26) & 0x3FFC0u)); \
    uint64_t *p3_ = (uint64_t *)((pj_ ^ 48u) + ((x_ >> 38) & 0x3FFC0u)); \
    uint32_t t_ = (S + 1u + ((uint32_t)(x_ >> 12) & 3u)) & 7u; \
    uint64_t m0_ = *p0_, m1_ = *p1_, m2_ = *p2_, m3_ = *p3_; \
    uint64_t k_ = r[W][t_], v_ = x_ ^ m0_ ^ m2_, y_, w13_ = m1_ ^ m3_; \
    uint64_t u_ = r[W][(S + 1) & 7] ^ w13_; \
    OPSWITCH_A(W, S) \
    r[W][S] = y_ ^ w13_; c##W = u_ ^ y_; \
    *p0_ = m0_ ^ y_; *p1_ = m1_ + x_; *p2_ = m2_ + y_; *p3_ = m3_ ^ x_; \
} while (0)
#endif

#define OPSWITCH(W, S) switch (op[W][S]) { \
    case 0: y_ = v_ * (k_ | 1); break; \
    case 1: y_ = v_ ^ (uint64_t)(((unsigned __int128)v_ * k_) >> 64); break; \
    case 2: y_ = v_ + k_ / ((uint64_t)(uint32_t)v_ | 0x80000001ull); break; \
    case 3: { uint64_t h_; AES_OP(v_, k_, y_, h_); r[W][t_] = k_ ^ h_; } break; \
    case 4: { unsigned n_ = (unsigned)k_ & 63u; y_ = (v_ >> n_) | (v_ << ((64u - n_) & 63u)); } break; \
    case 5: y_ = v_ + k_; break; \
    case 6: y_ = v_ - k_; break; \
    default: y_ = v_ ^ k_; break; \
    }
#define OPSWITCH_A(W, S) switch (op[W][S]) { \
    case 0: y_ = v_ * (k_ | 1); break; \
    case 1: y_ = v_ ^ (uint64_t)(((unsigned __int128)v_ * k_) >> 64); break; \
    case 2: y_ = v_ + k_ / ((uint64_t)(uint32_t)v_ | 0x80000001ull); break; \
    case 3: { uint64_t h_; AES_OP(v_, k_, y_, h_); r[W][t_] = k_ ^ h_; if (t_ == ((S + 1) & 7)) u_ ^= h_; } break; \
    case 4: { unsigned n_ = (unsigned)k_ & 63u; y_ = (v_ >> n_) | (v_ << ((64u - n_) & 63u)); } break; \
    case 5: y_ = v_ + k_; break; \
    case 6: y_ = v_ - k_; break; \
    default: y_ = v_ ^ k_; break; \
    }

/* the bodies for K = 1..4 */
#define WK 1
#include "walk_engine_body.h"
#undef WK
#define WK 2
#include "walk_engine_body.h"
#undef WK
#define WK 3
#include "walk_engine_body.h"
#undef WK
#define WK 4
#include "walk_engine_body.h"
#undef WK
#define WK 5
#include "walk_engine_body.h"
#undef WK
#define WK 6
#include "walk_engine_body.h"
#undef WK

/* one-time set-up (keys, tables); call before any walk */
void CAT3(walk_init_, ISA, )(void)
{
    wb3_init_keys();
#if defined(WE_SOFT)
    soft_init();
#endif
}
