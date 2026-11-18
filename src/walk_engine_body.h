/* SPDX-License-Identifier: GPL-3.0-or-later */
/* walk_engine_body.h - included by walk_engine.c with WK = 1..4 */
#ifdef WE_GOTO
#undef STEP
#define STEP STEPG
#endif
#if WK == 1
#define FOR_W(S) STEP(0, S);
#elif WK == 2
#define FOR_W(S) STEP(0, S); STEP(1, S);
#elif WK == 3
#define FOR_W(S) STEP(0, S); STEP(1, S); STEP(2, S);
#elif WK == 4
#define FOR_W(S) STEP(0, S); STEP(1, S); STEP(2, S); STEP(3, S);
#elif WK == 5
#define FOR_W(S) STEP(0, S); STEP(1, S); STEP(2, S); STEP(3, S); STEP(4, S);
#else
#define FOR_W(S) STEP(0, S); STEP(1, S); STEP(2, S); STEP(3, S); STEP(4, S); STEP(5, S);
#endif

int FNAME(WK)(const uint8_t mh[32], const uint64_t *nonce, uint8_t (*out)[32], uint64_t *pads,
              volatile const uint32_t *seqp, uint32_t seq)
{
    uint64_t r[WK][8] __attribute__((aligned(64)));
    uint8_t op[WK][8];
#ifdef WE_GOTO
#if WK == 1
    static const void *const tbl[WK][8][8] = { TBLW(0) };
#elif WK == 2
    static const void *const tbl[WK][8][8] = { TBLW(0), TBLW(1) };
#elif WK == 3
    static const void *const tbl[WK][8][8] = { TBLW(0), TBLW(1), TBLW(2) };
#elif WK == 4
    static const void *const tbl[WK][8][8] = { TBLW(0), TBLW(1), TBLW(2), TBLW(3) };
#elif WK == 5
    static const void *const tbl[WK][8][8] = { TBLW(0), TBLW(1), TBLW(2), TBLW(3), TBLW(4) };
#else
    static const void *const tbl[WK][8][8] = { TBLW(0), TBLW(1), TBLW(2), TBLW(3), TBLW(4), TBLW(5) };
#endif
    const void *jt[WK][8];
#define SET_JT() do { for (int w_ = 0; w_ < WK; w_++) for (int s_ = 0; s_ < 8; s_++) jt[w_][s_] = tbl[w_][s_][op[w_][s_]]; } while (0)
#else
#define SET_JT() do { } while (0)
#endif
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0;
    uint64_t *pad0 = pads, *pad1 = pads + 8 * W_LINES, *pad2 = pads + 16 * W_LINES, *pad3 = pads + 24 * W_LINES;
    uint64_t *pad4 = pads + 32 * W_LINES, *pad5 = pads + 40 * W_LINES;
    (void)c1; (void)c2; (void)c3; (void)c4; (void)c5; (void)pad1; (void)pad2; (void)pad3; (void)pad4; (void)pad5;
    for (int w = 0; w < WK; w++) walk_start(mh, nonce[w], r[w], op[w], pads + (size_t)w * 8 * W_LINES);
#ifdef WE_AHEAD
    /* c##W = x of the next step = r[s] ^ (previous output); at the start the output is 0 */
    c0 = r[0][0];
#if WK > 1
    c1 = r[1][0];
#endif
#if WK > 2
    c2 = r[2][0];
#endif
#if WK > 3
    c3 = r[3][0];
#endif
#if WK > 4
    c4 = r[4][0];
#endif
#if WK > 5
    c5 = r[5][0];
#endif
#endif
    SET_JT();
    for (uint32_t blk = 0; blk < W_STEPS / W_REMIX; blk++) {
        for (uint32_t i = 0; i < W_REMIX / 8; i++) {
            FOR_W(0) FOR_W(1) FOR_W(2) FOR_W(3) FOR_W(4) FOR_W(5) FOR_W(6) FOR_W(7)
        }
#ifdef WE_AHEAD
        /* the next x was computed from the old r[0]: redo it from the new r[0] and the last
           output, which is r[7] before the re-mix */
        uint64_t lastout[WK];
        for (int w = 0; w < WK; w++) { lastout[w] = r[w][7]; walk_remix(r[w], op[w]); }
        c0 = r[0][0] ^ lastout[0];
#if WK > 1
        c1 = r[1][0] ^ lastout[1];
#endif
#if WK > 2
        c2 = r[2][0] ^ lastout[2];
#endif
#if WK > 3
        c3 = r[3][0] ^ lastout[3];
#endif
#if WK > 4
        c4 = r[4][0] ^ lastout[4];
#endif
#if WK > 5
        c5 = r[5][0] ^ lastout[5];
#endif
#else
        for (int w = 0; w < WK; w++) walk_remix(r[w], op[w]);
#endif
        SET_JT();
        if (seqp && *seqp != seq) return 0;
    }
    for (int w = 0; w < WK; w++) walk_finish(mh, nonce[w], r[w], out[w]);
    return 1;
}
#undef FOR_W
#undef SET_JT
#ifdef WE_GOTO
#undef STEP
#endif
