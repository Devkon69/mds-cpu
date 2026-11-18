/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mds_blake3.h - BLAKE3 compression specialised for the Midstate (MDS) PoW.
 * Generated (by the gen_blake3.py of the mds-gpu project).
 *
 * One single-block BLAKE3 hash = one compression with cv = IV, counter = 0,
 * block_len = input length, flags = CHUNK_START | CHUNK_END | ROOT (11).
 * The 7 message schedules are expanded, so message words are plain arguments
 * and constant zero words (the chain step has m8..m15 = 0) fold away.
 * Usable from CUDA device code and from plain C (host reference / CPU tests). */
#ifndef MDS_BLAKE3_H
#define MDS_BLAKE3_H
#include <stdint.h>

#if defined(__CUDACC__)
#define MDS_FN __host__ __device__ __forceinline__
#elif defined(_MSC_VER)
#define MDS_FN static __forceinline
#else
#define MDS_FN static inline __attribute__((always_inline))
#endif

#define MDS_IV0 0x6A09E667u
#define MDS_IV1 0xBB67AE85u
#define MDS_IV2 0x3C6EF372u
#define MDS_IV3 0xA54FF53Au
#define MDS_IV4 0x510E527Fu
#define MDS_IV5 0x9B05688Cu
#define MDS_IV6 0x1F83D9ABu
#define MDS_IV7 0x5BE0CD19u
#define MDS_FLAGS 11u

/* rotations: on the GPU 16 and 8 are byte permutations (PRMT), 12 and 7 funnel shifts (SHF).
 * MDS_ROT_SHIFT=1 uses plain shift/or everywhere (A/B benchmark). */
#if defined(__CUDA_ARCH__) && !defined(MDS_ROT_SHIFT)
MDS_FN uint32_t mds_rotr16(uint32_t x) { return __byte_perm(x, 0, 0x1032); }
MDS_FN uint32_t mds_rotr8(uint32_t x)  { return __byte_perm(x, 0, 0x0321); }
MDS_FN uint32_t mds_rotr12(uint32_t x) { return __funnelshift_r(x, x, 12); }
MDS_FN uint32_t mds_rotr7(uint32_t x)  { return __funnelshift_r(x, x, 7); }
#else
MDS_FN uint32_t mds_rotr16(uint32_t x) { return (x >> 16) | (x << 16); }
MDS_FN uint32_t mds_rotr8(uint32_t x)  { return (x >> 8) | (x << 24); }
MDS_FN uint32_t mds_rotr12(uint32_t x) { return (x >> 12) | (x << 20); }
MDS_FN uint32_t mds_rotr7(uint32_t x)  { return (x >> 7) | (x << 25); }
#endif

/* additions: MDS_IMAD_ADD=1 routes every addition through mad.lo.u32 with a run-time
 * multiplier `one` (= 1), so ptxas keeps them on the FMA pipe (IMAD) instead of fusing
 * them into IADD3 on the ALU pipe, which also carries LOP3 / SHF / PRMT. */
#if defined(__CUDA_ARCH__) && defined(MDS_IMAD_ADD)
MDS_FN uint32_t mds_add(uint32_t a, uint32_t b, uint32_t one) { uint32_t r; asm("mad.lo.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(one), "r"(b)); return r; }
#define MDS_ADD(a, b) mds_add(a, b, one)
#else
#define MDS_ADD(a, b) ((a) + (b))
#endif

#define MDS_G(a, b, c, d, mx, my) do { \
    a = MDS_ADD(MDS_ADD(a, b), mx); d = mds_rotr16(d ^ a); c = MDS_ADD(c, d); b = mds_rotr12(b ^ c); \
    a = MDS_ADD(MDS_ADD(a, b), my); d = mds_rotr8(d ^ a);  c = MDS_ADD(c, d); b = mds_rotr7(b ^ c); \
} while (0)

/* out[0..7] = BLAKE3 hash words (little-endian) of the 64-byte block m0..m15
 * (input bytes as little-endian words, zero padded), input length blen <= 64. */
MDS_FN void mds_compress(uint32_t out[8], uint32_t m0, uint32_t m1, uint32_t m2, uint32_t m3, uint32_t m4, uint32_t m5, uint32_t m6, uint32_t m7, uint32_t m8, uint32_t m9, uint32_t m10, uint32_t m11, uint32_t m12, uint32_t m13, uint32_t m14, uint32_t m15, uint32_t blen, uint32_t one)
{
    uint32_t v0 = MDS_IV0, v1 = MDS_IV1, v2 = MDS_IV2, v3 = MDS_IV3;
    uint32_t v4 = MDS_IV4, v5 = MDS_IV5, v6 = MDS_IV6, v7 = MDS_IV7;
    uint32_t v8 = MDS_IV0, v9 = MDS_IV1, v10 = MDS_IV2, v11 = MDS_IV3;
    uint32_t v12 = 0u, v13 = 0u, v14 = blen, v15 = MDS_FLAGS;
    (void)one;
    /* round 0 */
    MDS_G(v0, v4, v8, v12, m0, m1);
    MDS_G(v1, v5, v9, v13, m2, m3);
    MDS_G(v2, v6, v10, v14, m4, m5);
    MDS_G(v3, v7, v11, v15, m6, m7);
    MDS_G(v0, v5, v10, v15, m8, m9);
    MDS_G(v1, v6, v11, v12, m10, m11);
    MDS_G(v2, v7, v8, v13, m12, m13);
    MDS_G(v3, v4, v9, v14, m14, m15);
    /* round 1 */
    MDS_G(v0, v4, v8, v12, m2, m6);
    MDS_G(v1, v5, v9, v13, m3, m10);
    MDS_G(v2, v6, v10, v14, m7, m0);
    MDS_G(v3, v7, v11, v15, m4, m13);
    MDS_G(v0, v5, v10, v15, m1, m11);
    MDS_G(v1, v6, v11, v12, m12, m5);
    MDS_G(v2, v7, v8, v13, m9, m14);
    MDS_G(v3, v4, v9, v14, m15, m8);
    /* round 2 */
    MDS_G(v0, v4, v8, v12, m3, m4);
    MDS_G(v1, v5, v9, v13, m10, m12);
    MDS_G(v2, v6, v10, v14, m13, m2);
    MDS_G(v3, v7, v11, v15, m7, m14);
    MDS_G(v0, v5, v10, v15, m6, m5);
    MDS_G(v1, v6, v11, v12, m9, m0);
    MDS_G(v2, v7, v8, v13, m11, m15);
    MDS_G(v3, v4, v9, v14, m8, m1);
    /* round 3 */
    MDS_G(v0, v4, v8, v12, m10, m7);
    MDS_G(v1, v5, v9, v13, m12, m9);
    MDS_G(v2, v6, v10, v14, m14, m3);
    MDS_G(v3, v7, v11, v15, m13, m15);
    MDS_G(v0, v5, v10, v15, m4, m0);
    MDS_G(v1, v6, v11, v12, m11, m2);
    MDS_G(v2, v7, v8, v13, m5, m8);
    MDS_G(v3, v4, v9, v14, m1, m6);
    /* round 4 */
    MDS_G(v0, v4, v8, v12, m12, m13);
    MDS_G(v1, v5, v9, v13, m9, m11);
    MDS_G(v2, v6, v10, v14, m15, m10);
    MDS_G(v3, v7, v11, v15, m14, m8);
    MDS_G(v0, v5, v10, v15, m7, m2);
    MDS_G(v1, v6, v11, v12, m5, m3);
    MDS_G(v2, v7, v8, v13, m0, m1);
    MDS_G(v3, v4, v9, v14, m6, m4);
    /* round 5 */
    MDS_G(v0, v4, v8, v12, m9, m14);
    MDS_G(v1, v5, v9, v13, m11, m5);
    MDS_G(v2, v6, v10, v14, m8, m12);
    MDS_G(v3, v7, v11, v15, m15, m1);
    MDS_G(v0, v5, v10, v15, m13, m3);
    MDS_G(v1, v6, v11, v12, m0, m10);
    MDS_G(v2, v7, v8, v13, m2, m6);
    MDS_G(v3, v4, v9, v14, m4, m7);
    /* round 6 */
    MDS_G(v0, v4, v8, v12, m11, m15);
    MDS_G(v1, v5, v9, v13, m5, m0);
    MDS_G(v2, v6, v10, v14, m1, m9);
    MDS_G(v3, v7, v11, v15, m8, m6);
    MDS_G(v0, v5, v10, v15, m14, m10);
    MDS_G(v1, v6, v11, v12, m2, m12);
    MDS_G(v2, v7, v8, v13, m3, m4);
    MDS_G(v3, v4, v9, v14, m7, m13);
    out[0] = v0 ^ v8;
    out[1] = v1 ^ v9;
    out[2] = v2 ^ v10;
    out[3] = v3 ^ v11;
    out[4] = v4 ^ v12;
    out[5] = v5 ^ v13;
    out[6] = v6 ^ v14;
    out[7] = v7 ^ v15;
}

/* one chain step: h = BLAKE3(h), h being 32 bytes. `one` must be 1 (see MDS_ADD). */
MDS_FN void mds_step(uint32_t h[8], uint32_t one)
{
    mds_compress(h, h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 32u, one);
}

/* seed: h = BLAKE3(midstate[32] || le64(nonce)), nonce = (uint64_t)hi << 32 | lo */
MDS_FN void mds_seed(uint32_t h[8], const uint32_t mid[8], uint32_t lo, uint32_t hi, uint32_t one)
{
    mds_compress(h, mid[0], mid[1], mid[2], mid[3], mid[4], mid[5], mid[6], mid[7],
                 lo, hi, 0u, 0u, 0u, 0u, 0u, 0u, 40u, one);
}

#define MDS_ITERS 1000000u
#endif
