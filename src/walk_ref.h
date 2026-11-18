/* SPDX-License-Identifier: GPL-3.0-or-later */
/* walk.h - Midstate Walk v1 proof of work (midstate >= v6.2.0, from block 371,500).
 * Written from the definition in ciphernom/midstate src/core/walk.rs; reproduces its
 * GOLDEN vectors (walk_selftest). Portable C (table-free AES, 64-bit integer ops). */
#ifndef WALK_H
#define WALK_H
#include <stdint.h>
#define WALK_ACTIVATION_HEIGHT 371500ULL
void walk_hash(const uint8_t mining_hash[32], uint64_t nonce, uint8_t out[32]);
int  walk_selftest(void);       /* 1 = the three golden vectors match */
#endif
