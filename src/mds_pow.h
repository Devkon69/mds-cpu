/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mds_pow.h - Midstate (MDS) proof of work: 1,000,001 single-block BLAKE3 compressions.
 *   x0 = BLAKE3(midstate || le64(nonce)); x_k = BLAKE3(x_{k-1}), k = 1..iters
 * Bit-exact with ciphernom/midstate src/core/extension.rs (create_extension). */
#ifndef MDS_POW_H
#define MDS_POW_H
#include <stdint.h>
#define MDS_ITERS 1000000u
void mds_blake3_small(const uint8_t *in, unsigned len, uint8_t out[32]);   /* len <= 64 */
void mds_extension(const uint8_t midstate[32], uint64_t nonce, uint32_t iters, uint8_t out[32]);
int  mds_hash_lt(const uint8_t a[32], const uint8_t b[32]);                 /* a < b, big-endian */
#endif
