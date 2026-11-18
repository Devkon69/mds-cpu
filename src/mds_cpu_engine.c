/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mds_cpu_engine.c - multi-lane MDS chain on SIMD vectors.
 *
 * Compiled once per instruction set with one of
 *   -DENG_SSE2      4 lanes  (any x86-64)
 *   -DENG_AVX2      8 lanes  (-mavx2)
 *   -DENG_AVX512VL  8 lanes  (-mavx512f -mavx512vl: 256-bit vectors, native rotate, 32 registers)
 *   -DENG_AVX512   16 lanes  (-mavx512f)
 * Every lane runs its own nonce chain; NG = 1 or 2 independent lane groups are interleaved.
 *
 *   int mds_chain_<isa>_g<NG>(mid, hi, lo0, iters, out, seqp, seq)
 * runs nonces (hi << 32 | lo0 + i), i = 0 .. NG*LANES-1, for 1 seed + `iters` steps and writes
 * the final hash words to out[i * 8 + w]. Every 32768 steps it compares *seqp with seq and
 * returns 0 (aborted) if they differ; 1 when done. */
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#include "mds_cpu_core.h"

#if defined(ENG_AVX512)
#define LANES 16
#define ISA avx512
typedef uint32_t V __attribute__((vector_size(64), aligned(64)));
#define R16(x) ((V)_mm512_ror_epi32((__m512i)(x), 16))
#define R12(x) ((V)_mm512_ror_epi32((__m512i)(x), 12))
#define R8(x)  ((V)_mm512_ror_epi32((__m512i)(x), 8))
#define R7(x)  ((V)_mm512_ror_epi32((__m512i)(x), 7))
#elif defined(ENG_AVX512VL)
#define LANES 8
#define ISA avx512vl
typedef uint32_t V __attribute__((vector_size(32), aligned(32)));
#define R16(x) ((V)_mm256_ror_epi32((__m256i)(x), 16))
#define R12(x) ((V)_mm256_ror_epi32((__m256i)(x), 12))
#define R8(x)  ((V)_mm256_ror_epi32((__m256i)(x), 8))
#define R7(x)  ((V)_mm256_ror_epi32((__m256i)(x), 7))
#elif defined(ENG_AVX2)
#define LANES 8
#define ISA avx2
typedef uint32_t V __attribute__((vector_size(32), aligned(32)));
#define ROT16M _mm256_setr_epi8(2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13, 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13)
#define ROT8M  _mm256_setr_epi8(1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12, 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12)
#define R16(x) ((V)_mm256_shuffle_epi8((__m256i)(x), ROT16M))
#define R8(x)  ((V)_mm256_shuffle_epi8((__m256i)(x), ROT8M))
#define R12(x) (((x) >> 12) | ((x) << 20))
#define R7(x)  (((x) >> 7) | ((x) << 25))
#elif defined(ENG_SSE2)
#define LANES 4
#define ISA sse2
typedef uint32_t V __attribute__((vector_size(16), aligned(16)));
#define R16(x) ((V)_mm_shufflehi_epi16(_mm_shufflelo_epi16((__m128i)(x), 0xB1), 0xB1))
#define R12(x) (((x) >> 12) | ((x) << 20))
#define R8(x)  (((x) >> 8) | ((x) << 24))
#define R7(x)  (((x) >> 7) | ((x) << 25))
#else
#error "define ENG_SSE2 / ENG_AVX2 / ENG_AVX512VL / ENG_AVX512"
#endif

#define ADD(a, b) ((a) + (b))
#define XOR(a, b) ((a) ^ (b))
#define C(k) (((V){0}) + (uint32_t)(k))

#define CAT_(a, b, c) mds_chain_##a##_g##b##c
#define FN(isa, ng) CAT_(isa, ng, )
#define CHECK_EVERY 32768u

static inline void store8(uint32_t *out, int base, V h0, V h1, V h2, V h3, V h4, V h5, V h6, V h7)
{
    uint32_t t[8][LANES] __attribute__((aligned(64)));
    memcpy(t[0], &h0, sizeof h0); memcpy(t[1], &h1, sizeof h1); memcpy(t[2], &h2, sizeof h2); memcpy(t[3], &h3, sizeof h3);
    memcpy(t[4], &h4, sizeof h4); memcpy(t[5], &h5, sizeof h5); memcpy(t[6], &h6, sizeof h6); memcpy(t[7], &h7, sizeof h7);
    for (int l = 0; l < LANES; l++) for (int w = 0; w < 8; w++) out[(base + l) * 8 + w] = t[w][l];
}

static inline V lane_ids(void)
{
    V r; for (int i = 0; i < LANES; i++) r[i] = (uint32_t)i;
    return r;
}

int FN(ISA, 1)(const uint32_t mid[8], uint32_t hi, uint32_t lo0, uint32_t iters, uint32_t *out,
               volatile const uint32_t *seqp, uint32_t seq)
{
    V mid0 = C(mid[0]), mid1 = C(mid[1]), mid2 = C(mid[2]), mid3 = C(mid[3]);
    V mid4 = C(mid[4]), mid5 = C(mid[5]), mid6 = C(mid[6]), mid7 = C(mid[7]);
    V lo = C(lo0) + lane_ids(), vhi = C(hi);
    V h0, h1, h2, h3, h4, h5, h6, h7;
    MDS_SEED_G1(h, mid, lo, vhi);
    uint32_t k = 0;
    while (k < iters) {
        uint32_t end = iters - k > CHECK_EVERY ? k + CHECK_EVERY : iters;
        for (; k < end; k++) MDS_STEP_G1(h);
        if (seqp && *seqp != seq) return 0;
    }
    store8(out, 0, h0, h1, h2, h3, h4, h5, h6, h7);
    return 1;
}

int FN(ISA, 2)(const uint32_t mid[8], uint32_t hi, uint32_t lo0, uint32_t iters, uint32_t *out,
               volatile const uint32_t *seqp, uint32_t seq)
{
    V mid0 = C(mid[0]), mid1 = C(mid[1]), mid2 = C(mid[2]), mid3 = C(mid[3]);
    V mid4 = C(mid[4]), mid5 = C(mid[5]), mid6 = C(mid[6]), mid7 = C(mid[7]);
    V loa = C(lo0) + lane_ids(), lob = loa + (uint32_t)LANES, vhi = C(hi);
    V h0, h1, h2, h3, h4, h5, h6, h7;
    V g0, g1, g2, g3, g4, g5, g6, g7;
    MDS_SEED_G1(h, mid, loa, vhi);
    MDS_SEED_G1(g, mid, lob, vhi);
    uint32_t k = 0;
    while (k < iters) {
        uint32_t end = iters - k > CHECK_EVERY ? k + CHECK_EVERY : iters;
        for (; k < end; k++) MDS_STEP_G2(h, g);
        if (seqp && *seqp != seq) return 0;
    }
    store8(out, 0, h0, h1, h2, h3, h4, h5, h6, h7);
    store8(out, LANES, g0, g1, g2, g3, g4, g5, g6, g7);
    return 1;
}
