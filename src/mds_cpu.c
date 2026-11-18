/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
/* mds-cpu - Midstate (MDS) miner for x86-64 CPUs (Windows and Linux).
 *
 * PoW (ciphernom/midstate, src/core/extension.rs): one nonce = a chain of 1,000,001
 * single-block BLAKE3 compressions
 *     x0 = BLAKE3(mining_hash[32] || le64(nonce)),  x_k = BLAKE3(x_{k-1}),  k = 1..1,000,000
 * and the share is valid when x_1000000 < target (256-bit big-endian compare).
 *
 * The chain is strictly sequential, so the parallelism is across nonces: every SIMD lane
 * runs its own chain (SSE2 4, AVX2 8, AVX-512 16 lanes, optionally two groups interleaved),
 * one worker thread per logical CPU. The engines are in mds_cpu_engine.c (compiled once per
 * instruction set, chosen at run time). The pool client is the one of mds-gpu (LuckyPool
 * dialect and classic stratum, TLS with mbedtls).
 *
 *   mds-cpu --pool stratum+ssl://eu.lproute.com:8960 --user MSS_ADDRESS.rig
 *   mds-cpu --bench 30        mds-cpu --test        mds-cpu --tune
 */
#include "platform.h"
#include <math.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include "mds_blake3.h"
#include "walk_ref.h"
#include "cJSON.h"
#ifndef _WIN32
#include <sched.h>
#include <sys/mman.h>
#endif

#ifndef NO_TLS
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/net_sockets.h"
#include "ca_bundle.h"
#endif

#define VERSION "0.3.1"
#define MAX_THREADS 256
#define MAX_LANES 32

/* ------------------------------------------------------------------ dev fee
   FEE_PCT % of the mining time goes to the developer (FEE_ADDR, and FEE_MWB for merged-mined
   midwimble), in short windows on the same pool, announced at start-up and in --help.
   Default 2; build with FEE=0 (-DFEE_PCT=0) for no fee. */
#ifndef FEE_PCT
#define FEE_PCT 2
#endif
#ifndef FEE_ADDR
#define FEE_ADDR "66d967a278d0faceba275fa9ac537fd08fe430f0860cb5b3ba24d0d8dceaf1422f6e0920"
#endif
/* midwimble address of the fee windows (merged mining: password field on LuckyPool, 3rd
   mining.authorize parameter on a midstate pool) */
#ifndef FEE_MWB
#define FEE_MWB "mw1qy7tjtsu4nz00tcqgkcqjyyxmjzvzwd6rjtvjcnh364ccvj8gw6rew4cxe5dxsqmzwrl7yp7dq8gnrk8na99dlpc2f58p8j06999m7r7ztmamvtwsgq68d3r5agmja5qqz448kjxalrrez9yxakzme6d29wqhgj5pc"
#endif
#ifndef FEE_CYCLE
#define FEE_CYCLE 6000.0
#endif
#define FEE_SECS (FEE_CYCLE * FEE_PCT / 100.0)

/* ============================================================== options */
static struct {
    const char *pools[8]; int npools;
    const char *user, *pass, *rig, *log_file, *engine;
    int threads, priority, affinity;
    int bench, test, tune, pool_log, insecure, verbose, dialect;
    double stats_s, verify_s;
    int algo;                     /* 0 auto (job height / pow, Walk if unknown), 1 BLAKE3 chain, 2 Walk */
    int walk_k;                   /* walks stepped in turn per thread (0 = auto) */
    const char *walk_isa;         /* auto, v3, aesni, soft */
    int huge;                     /* large pages for the scratchpads */
    double failback_s;            /* on a fallback pool: try the first one again after this (0 = never) */
    int calibrate;                /* measure 1..4 walks per thread at start when --walk-k is not given */
    double share_rate;            /* most shares per second sent (0 = no limit) */
    const char *midwimble;        /* midwimble payout address (3rd mining.authorize parameter) */
    unsigned long long walk_height;
} opt = { {0}, 0, NULL, "x", "cpu", NULL, "auto", 0, 1, 0, 0, 0, 0, 0, 0, 0, -2, 30.0, 60.0,
          0, 0, "auto", 1, 900.0, 1, 2.0, NULL, 371500ULL };

static volatile int g_stop;
static volatile int g_exited;     /* main has cleaned up */
static void on_sig(int s) { (void)s; g_stop = 1; }

/* ============================================================== log */
static pthread_mutex_t log_mx = PTHREAD_MUTEX_INITIALIZER;
static FILE *log_fp;
static void logm(const char *fmt, ...)
{
    char ts[32]; time_t t = time(NULL); struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    char msg[2048];
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    pthread_mutex_lock(&log_mx);
    printf("%s %s\n", ts, msg); fflush(stdout);
    if (log_fp) { fprintf(log_fp, "%s %s\n", ts, msg); fflush(log_fp); }
    pthread_mutex_unlock(&log_mx);
}

/* ============================================================== helpers */
static int ci_eq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    return *a == *b;
}
static const char *ci_str(const char *h, const char *n)
{
    size_t ln = strlen(n);
    for (; *h; h++) { size_t i = 0; while (i < ln && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)n[i])) i++; if (i == ln) return h; }
    return NULL;
}
static uint64_t rnd64(void)
{
    static uint64_t s; static int init;
    if (!init) { s = (uint64_t)time(NULL) * 6364136223846793005ULL ^ ((uint64_t)(uintptr_t)&init << 17) ^ (uint64_t)(now_s() * 1e9) ^ ((uint64_t)clock() << 32); if (!s) s = 88172645463325252ULL; init = 1; }
    s ^= s << 13; s ^= s >> 7; s ^= s << 17;
    return s * 2685821657736338717ULL;
}
static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static int hex_to(const char *s, uint8_t *o, int n)
{
    if (!s || (int)strlen(s) < 2 * n) return -1;
    for (int i = 0; i < n; i++) { int a = hexv(s[2 * i]), b = hexv(s[2 * i + 1]); if (a < 0 || b < 0) return -1; o[i] = (uint8_t)(a << 4 | b); }
    return 0;
}
static void hex_of(const uint8_t *b, int n, char *out) { for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]); out[2 * n] = 0; }
static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static void put_le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* difficulty of a 256-bit big-endian target: 2^64 / (top 64 bits + 1) */
static double diff_of(const uint8_t *v)
{
    uint64_t top = 0;
    for (int i = 0; i < 8; i++) top = top << 8 | v[i];
    return 18446744073709551616.0 / ((double)top + 1.0);
}
static int target_bits(const uint8_t *t)
{
    int bits = 0;
    for (int b = 0; b < 256 && !((t[b / 8] >> (7 - b % 8)) & 1); b++) bits++;
    return bits;
}

/* CPU reference: the full chain, with the same generated code as the kernel */
static void cpu_chain(const uint8_t mid[32], uint64_t nonce, uint32_t iters, uint32_t h[8])
{
    uint32_t m[8];
    for (int i = 0; i < 8; i++) m[i] = le32(mid + 4 * i);
    mds_seed(h, m, (uint32_t)nonce, (uint32_t)(nonce >> 32), 1u);
    for (uint32_t k = 0; k < iters; k++) mds_step(h, 1u);
}
static void hash_bytes(const uint32_t h[8], uint8_t out[32]) { for (int i = 0; i < 8; i++) put_le32(out + 4 * i, h[i]); }
static int hash_lt(const uint8_t a[32], const uint8_t b[32]) { return memcmp(a, b, 32) < 0; }

/* ============================================================== jobs */
typedef struct {
    uint8_t mid[32];
    uint8_t target[32];           /* share target, big-endian */
    uint64_t prefix; int free_bits;   /* nonce = prefix << free_bits | ours (free_bits >= 32) */
    char pool_job[96];            /* job id as JSON text */
    uint32_t seq;                 /* 0 = no job */
    int fee;                      /* mined for the dev fee address */
    int clean;                    /* the pool wants the old work dropped (new block) */
    int walk;                     /* proof of work: 1 Midstate Walk, 0 BLAKE3 chain */
    long long height;             /* block height from the pool, -1 = not given */
} job_t;

static pthread_mutex_t job_mx = PTHREAD_MUTEX_INITIALIZER;
static job_t cur_job;             /* protected by job_mx */

/* candidates from the GPUs to the pool thread */
typedef struct { uint32_t seq; uint64_t nonce; uint8_t hash[32]; int gpu; } cand_t;
static pthread_mutex_t cand_mx = PTHREAD_MUTEX_INITIALIZER;
static cand_t cands[1024]; static int ncands;
static long cand_dropped;

static void push_cand(uint32_t seq, uint64_t nonce, const uint8_t *hash, int gpu)
{
    pthread_mutex_lock(&cand_mx);
    if (ncands < 1024) { cand_t *c = &cands[ncands++]; c->seq = seq; c->nonce = nonce; memcpy(c->hash, hash, 32); c->gpu = gpu; }
    else cand_dropped++;
    pthread_mutex_unlock(&cand_mx);
}


/* ============================================================== engines */
typedef int (*chain_fn)(const uint32_t mid[8], uint32_t hi, uint32_t lo0, uint32_t iters, uint32_t *out,
                        volatile const uint32_t *seqp, uint32_t seq);
#define DECL(n) int n(const uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t *, volatile const uint32_t *, uint32_t);
DECL(mds_chain_sse2_g1) DECL(mds_chain_sse2_g2) DECL(mds_chain_avx2_g1) DECL(mds_chain_avx2_g2)
DECL(mds_chain_avx512vl_g1) DECL(mds_chain_avx512vl_g2) DECL(mds_chain_avx512_g1) DECL(mds_chain_avx512_g2)

typedef struct { const char *name; chain_fn fn; int lanes; int isa; const char *desc; } engine_t;
enum { ISA_SSE2, ISA_AVX2, ISA_AVX512VL, ISA_AVX512 };
static const engine_t engines[] = {
    { "avx512x2",   mds_chain_avx512_g2,   32, ISA_AVX512,   "AVX-512, 2 x 16 lanes" },
    { "avx512",     mds_chain_avx512_g1,   16, ISA_AVX512,   "AVX-512, 16 lanes" },
    { "avx512vlx2", mds_chain_avx512vl_g2, 16, ISA_AVX512VL, "AVX-512VL 256-bit, 2 x 8 lanes" },
    { "avx512vl",   mds_chain_avx512vl_g1,  8, ISA_AVX512VL, "AVX-512VL 256-bit, 8 lanes" },
    { "avx2x2",     mds_chain_avx2_g2,     16, ISA_AVX2,     "AVX2, 2 x 8 lanes" },
    { "avx2",       mds_chain_avx2_g1,      8, ISA_AVX2,     "AVX2, 8 lanes" },
    { "sse2x2",     mds_chain_sse2_g2,      8, ISA_SSE2,     "SSE2, 2 x 4 lanes" },
    { "sse2",       mds_chain_sse2_g1,      4, ISA_SSE2,     "SSE2, 4 lanes" },
};
#define NENGINES (int)(sizeof engines / sizeof *engines)
static const engine_t *eng;

static int isa_ok(int isa)
{
    __builtin_cpu_init();
    switch (isa) {
    case ISA_AVX512:   return __builtin_cpu_supports("avx512f");
    case ISA_AVX512VL: return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl");
    case ISA_AVX2:     return __builtin_cpu_supports("avx2");
    default:           return 1;
    }
}
static const engine_t *engine_by_name(const char *n)
{
    for (int i = 0; i < NENGINES; i++) if (ci_eq(n, engines[i].name)) return &engines[i];
    return NULL;
}
/* default: the first supported engine of the list (widest vectors, two groups) */
static const engine_t *engine_auto(void)
{
    for (int i = 0; i < NENGINES; i++) if (isa_ok(engines[i].isa)) return &engines[i];
    return &engines[NENGINES - 1];
}

/* ============================================================== CPU info */
static char cpu_brand[64];
static int n_logical, n_cores;

static void cpu_info(void)
{
    unsigned int r[12] = {0};
#if defined(__x86_64__) || defined(__i386__)
    unsigned int a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000000u), "c"(0));
    if (a >= 0x80000004u)
        for (unsigned int i = 0; i < 3; i++)
            __asm__ volatile("cpuid" : "=a"(r[4 * i]), "=b"(r[4 * i + 1]), "=c"(r[4 * i + 2]), "=d"(r[4 * i + 3]) : "a"(0x80000002u + i), "c"(0));
#endif
    memcpy(cpu_brand, r, 48); cpu_brand[48] = 0;
    char *s = cpu_brand; while (*s == ' ') s++;
    memmove(cpu_brand, s, strlen(s) + 1);
    for (int i = (int)strlen(cpu_brand) - 1; i >= 0 && cpu_brand[i] == ' '; i--) cpu_brand[i] = 0;
    if (!cpu_brand[0]) strcpy(cpu_brand, "unknown CPU");
#ifdef _WIN32
    n_logical = (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (len) {
        char *buf = malloc(len);
        if (buf && GetLogicalProcessorInformationEx(RelationProcessorCore, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf, &len)) {
            for (DWORD off = 0; off < len;) {
                PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX e = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(buf + off);
                if (e->Relationship == RelationProcessorCore) n_cores++;
                off += e->Size;
            }
        }
        free(buf);
    }
#else
    n_logical = (int)sysconf(_SC_NPROCESSORS_ONLN);
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256]; int phys = 0, seen[1024], ns = 0;
        while (fgets(line, sizeof line, f)) {
            if (!strncmp(line, "physical id", 11)) phys = atoi(strchr(line, ':') + 1);
            else if (!strncmp(line, "core id", 7)) {
                int key = phys * 4096 + atoi(strchr(line, ':') + 1), dup = 0;
                for (int i = 0; i < ns; i++) if (seen[i] == key) dup = 1;
                if (!dup && ns < 1024) seen[ns++] = key;
            }
        }
        fclose(f); n_cores = ns;
    }
#endif
    if (n_logical < 1) n_logical = 1;
    if (n_cores < 1 || n_cores > n_logical) n_cores = n_logical;
}

/* ============================================================== Midstate Walk engines */
typedef int (*walk_fn)(const uint8_t mh[32], const uint64_t *nonce, uint8_t (*out)[32], uint64_t *pads,
                       volatile const uint32_t *seqp, uint32_t seq);
#define WDECL(i) \
    int walk_k1_##i(const uint8_t *, const uint64_t *, uint8_t (*)[32], uint64_t *, volatile const uint32_t *, uint32_t); \
    int walk_k2_##i(const uint8_t *, const uint64_t *, uint8_t (*)[32], uint64_t *, volatile const uint32_t *, uint32_t); \
    int walk_k3_##i(const uint8_t *, const uint64_t *, uint8_t (*)[32], uint64_t *, volatile const uint32_t *, uint32_t); \
    int walk_k4_##i(const uint8_t *, const uint64_t *, uint8_t (*)[32], uint64_t *, volatile const uint32_t *, uint32_t); \
    int walk_k5_##i(const uint8_t *, const uint64_t *, uint8_t (*)[32], uint64_t *, volatile const uint32_t *, uint32_t); \
    int walk_k6_##i(const uint8_t *, const uint64_t *, uint8_t (*)[32], uint64_t *, volatile const uint32_t *, uint32_t); \
    void walk_init_##i(void);
WDECL(v3) WDECL(aesni) WDECL(soft)
#define WALK_MAX_K 6
#define WALK_PAD_BYTES (4096u * 64u)
typedef struct { const char *name; walk_fn fn[WALK_MAX_K]; int isa; const char *desc; } walk_engine_t;
enum { WISA_SOFT, WISA_AESNI, WISA_V3 };
static const walk_engine_t walk_engines[] = {
    { "v3",    { walk_k1_v3, walk_k2_v3, walk_k3_v3, walk_k4_v3, walk_k5_v3, walk_k6_v3 }, WISA_V3, "AES-NI + AVX2/BMI2 code" },
    { "aesni", { walk_k1_aesni, walk_k2_aesni, walk_k3_aesni, walk_k4_aesni, walk_k5_aesni, walk_k6_aesni }, WISA_AESNI, "AES-NI" },
    { "soft",  { walk_k1_soft, walk_k2_soft, walk_k3_soft, walk_k4_soft, walk_k5_soft, walk_k6_soft }, WISA_SOFT, "portable AES tables" },
};
#define NWALK (int)(sizeof walk_engines / sizeof *walk_engines)
static const walk_engine_t *weng;

static int walk_isa_ok(int isa)
{
    __builtin_cpu_init();
    switch (isa) {
    case WISA_V3:    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2") &&
                            __builtin_cpu_supports("fma") && __builtin_cpu_supports("sse4.2");
    case WISA_AESNI: return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse4.1");
    default:         return 1;
    }
}
static const walk_engine_t *walk_engine_auto(void)
{
    for (int i = 0; i < NWALK; i++) if (walk_isa_ok(walk_engines[i].isa)) return &walk_engines[i];
    return &walk_engines[NWALK - 1];
}
static void walk_init_all(void) { walk_init_v3(); walk_init_aesni(); walk_init_soft(); }

/* ---------------------------------------------------------- scratchpad memory (large pages) */
static volatile int huge_ok_count, huge_fail_count;
#ifdef _WIN32
static SIZE_T large_page_size;
static int large_pages_privilege(void)
{
    static int done = 0, ok = 0;
    if (done) return ok;
    done = 1;
    HANDLE tok;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        TOKEN_PRIVILEGES tp; tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &tp.Privileges[0].Luid) &&
            AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS) ok = 1;
        CloseHandle(tok);
    }
    large_page_size = GetLargePageMinimum();
    if (!large_page_size) ok = 0;
    return ok;
}
#endif
/* bytes rounded up; *huge = 1 when large pages were used. 64-byte (at least) aligned. */
static void *pad_alloc(size_t bytes, int *huge)
{
    *huge = 0;
#ifdef _WIN32
    if (opt.huge && large_pages_privilege()) {
        size_t sz = (bytes + large_page_size - 1) & ~(large_page_size - 1);
        void *p = VirtualAlloc(NULL, sz, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
        if (p) { *huge = 1; return p; }
    }
    return VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
    size_t two = 2u << 20, sz = (bytes + two - 1) & ~(two - 1);
    void *p = mmap(NULL, sz + two, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    uintptr_t a = ((uintptr_t)p + two - 1) & ~(uintptr_t)(two - 1);
    if (opt.huge && madvise((void *)a, sz, MADV_HUGEPAGE) == 0) *huge = 1;
    return (void *)a;   /* never freed back exactly (worker exit is process exit or bench end) */
#endif
}
static void pad_free(void *p)
{
#ifdef _WIN32
    if (p) VirtualFree(p, 0, MEM_RELEASE);
#else
    (void)p;   /* kept: bench/tune re-create workers a few times only */
#endif
}

#ifdef _WIN32
/* --setup-large-pages: give this user "Lock pages in memory" (needs an administrator console;
   takes effect after signing out and in again, or a reboot) */
#include <ntsecapi.h>
static int setup_large_pages(void)
{
    HANDLE tok; DWORD len = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &len);
    TOKEN_USER *tu = malloc(len);
    if (!tu || !GetTokenInformation(tok, TokenUser, tu, len, &len)) { CloseHandle(tok); free(tu); return 0; }
    CloseHandle(tok);
    LSA_OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof oa);
    LSA_HANDLE pol;
    NTSTATUS st = LsaOpenPolicy(NULL, &oa, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &pol);
    if (st) { logm("large pages: LsaOpenPolicy failed (0x%lx) - run this from an administrator console", (unsigned long)LsaNtStatusToWinError(st)); free(tu); return 0; }
    WCHAR name[] = L"SeLockMemoryPrivilege";
    LSA_UNICODE_STRING us; us.Buffer = name; us.Length = (USHORT)(wcslen(name) * sizeof(WCHAR)); us.MaximumLength = us.Length + sizeof(WCHAR);
    st = LsaAddAccountRights(pol, tu->User.Sid, &us, 1);
    LsaClose(pol); free(tu);
    if (st) { logm("large pages: LsaAddAccountRights failed (0x%lx) - run this from an administrator console", (unsigned long)LsaNtStatusToWinError(st)); return 0; }
    logm("large pages: \"Lock pages in memory\" granted to this user - sign out and in again (or reboot), then start the miner");
    return 1;
}
#endif

/* ============================================================== workers */
typedef struct {
    int idx; pthread_t th; int started;
    volatile double nonces;
    volatile double lost_s;           /* thread time thrown away on new blocks */
    volatile long batches, aborted, jobs, jobs_clean, found;
    volatile int alive;
} worker_t;
static worker_t workers[MAX_THREADS]; static int nworkers;
static volatile int w_quit;           /* stop the workers (bench / tune) */
/* bumped (under job_mx) when the running batches must be dropped: new block, connection
   lost, dev fee switch. A job of the same block does not bump it: the batches finish and
   their shares go out with their own job id. */
static volatile uint32_t g_abort_seq = 1;

static void thread_setup(int idx)
{
#ifdef _WIN32
    static const int prio[6] = { THREAD_PRIORITY_IDLE, THREAD_PRIORITY_LOWEST, THREAD_PRIORITY_BELOW_NORMAL,
                                 THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL, THREAD_PRIORITY_HIGHEST };
    if (opt.priority >= 0 && opt.priority <= 5) SetThreadPriority(GetCurrentThread(), prio[opt.priority]);
    if (opt.affinity && n_logical <= 64) {
        int cpu = (nworkers <= n_cores && n_logical == 2 * n_cores) ? 2 * idx : idx % n_logical;
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << cpu);
    }
#else
    if (opt.affinity) {
        cpu_set_t s; CPU_ZERO(&s);
        int cpu = idx % n_logical;
        CPU_SET(cpu, &s); pthread_setaffinity_np(pthread_self(), sizeof s, &s);
    }
#endif
}

/* nonce layout: low 32 bits = thread index (8 bits) : counter (24 bits);
   bits 32.. = pool prefix (extranonce) and, when the pool leaves more than 32 free bits,
   random bits so that reconnections do not repeat nonces */
static uint32_t job_hi(const job_t *j, uint64_t salt)
{
    if (j->free_bits >= 64) return (uint32_t)(salt >> 32);
    uint64_t extra = j->free_bits > 32 ? (salt & ((1ULL << (j->free_bits - 32)) - 1)) : 0;
    return (uint32_t)((j->prefix << (j->free_bits - 32)) | extra);
}

/* sample verification with the scalar reference code (catches unstable CPU settings,
   e.g. an aggressive Curve Optimizer / undervolt) */
typedef struct { uint8_t mid[32]; uint64_t nonce; uint8_t hb[32]; int thr, walk; } vreq_t;
static pthread_mutex_t ver_mx = PTHREAD_MUTEX_INITIALIZER;
static vreq_t ver_q[64]; static int nver;
static double ver_last;
static volatile long ver_done, ver_bad;

static void *verifier_thread(void *a)
{
    (void)a;
    while (!g_stop) {
        vreq_t v; int have = 0;
        pthread_mutex_lock(&ver_mx);
        if (nver) { v = ver_q[--nver]; have = 1; }
        pthread_mutex_unlock(&ver_mx);
        if (!have) { sleep_ms(100); continue; }
        uint8_t hb[32];
        if (v.walk) walk_hash(v.mid, v.nonce, hb);          /* portable reference, walk_ref.c */
        else { uint32_t h[8]; cpu_chain(v.mid, v.nonce, MDS_ITERS, h); hash_bytes(h, hb); }
        ver_done++;
        if (memcmp(hb, v.hb, 32)) {
            ver_bad++;
            logm("T%d: WRONG %s hash for nonce %016llx (check failed: unstable CPU overclock/undervolt?)", v.thr, v.walk ? "Walk" : "chain", (unsigned long long)v.nonce);
        } else if (opt.verbose) logm("T%d: sample %s nonce %016llx verified", v.thr, v.walk ? "Walk" : "chain", (unsigned long long)v.nonce);
    }
    return NULL;
}

static void maybe_verify(const job_t *job, uint64_t nonce, const uint8_t hb[32], int thr, double t)
{
    if (opt.verify_s <= 0 || w_quit || t - ver_last < opt.verify_s) return;
    pthread_mutex_lock(&ver_mx);
    if (t - ver_last >= opt.verify_s && nver < 64) {
        vreq_t *v = &ver_q[nver++]; memcpy(v->mid, job->mid, 32); v->nonce = nonce; memcpy(v->hb, hb, 32); v->thr = thr; v->walk = job->walk;
        ver_last = t;
    }
    pthread_mutex_unlock(&ver_mx);
}

static int walk_k_eff;   /* walks per thread actually used */

static void *worker_thread(void *a)
{
    worker_t *w = (worker_t *)a;
    thread_setup(w->idx);
    uint32_t out[MAX_LANES * 8] __attribute__((aligned(64)));
    uint8_t wout[WALK_MAX_K][32];
    uint64_t *pads = NULL; int pads_k = 0;
    job_t job; memset(&job, 0, sizeof job);
    uint32_t mid[8] = {0}, counter = 0, hi = 0, exhausted = 0, abort_seq = 0;
    w->alive = 1;
    while (!g_stop && !w_quit) {
        pthread_mutex_lock(&job_mx);
        int changed = cur_job.seq != job.seq;
        if (changed) job = cur_job;
        abort_seq = g_abort_seq;
        pthread_mutex_unlock(&job_mx);
        if (changed && job.seq) {
            w->jobs++; if (job.clean) w->jobs_clean++;
            hi = job_hi(&job, rnd64());
            /* random start: after a re-login (dev fee window, reconnection) the same job with the
               same extranonce does not repeat the nonces already sent */
            counter = (uint32_t)rnd64() & 0x007FFFFFu;
            for (int i = 0; i < 8; i++) mid[i] = le32(job.mid + 4 * i);
        }
        if (!job.seq || job.seq == exhausted) { sleep_ms(20); continue; }
        const int lanes = job.walk ? walk_k_eff : eng->lanes;
        if (counter + (uint32_t)lanes > 0x01000000u) {
            logm("T%d: nonce space of this job exhausted, waiting for a new job", w->idx);
            exhausted = job.seq; continue;
        }
        uint32_t lo0 = ((uint32_t)w->idx << 24) | counter;
        counter += lanes;
        double t0 = now_s();
        if (job.walk) {
            if (pads_k < lanes) {
                int huge;
                pad_free(pads);
                pads = pad_alloc((size_t)lanes * WALK_PAD_BYTES, &huge);
                if (!pads) { logm("T%d: cannot allocate %d KiB for the scratchpads", w->idx, lanes * 256); w->alive = 0; return NULL; }
                pads_k = lanes;
                if (huge) __sync_fetch_and_add(&huge_ok_count, 1); else __sync_fetch_and_add(&huge_fail_count, 1);
            }
            uint64_t nn[WALK_MAX_K];
            for (int i = 0; i < lanes; i++) nn[i] = (uint64_t)hi << 32 | (uint32_t)(lo0 + i);
            if (!weng->fn[lanes - 1](job.mid, nn, wout, pads, &g_abort_seq, abort_seq)) {
                w->aborted++; w->lost_s += now_s() - t0;
                continue;
            }
            w->batches++; w->nonces += lanes;
            double t = now_s();
            for (int l = 0; l < lanes; l++) {
                if (hash_lt(wout[l], job.target)) { w->found++; push_cand(job.seq, nn[l], wout[l], w->idx); }
                if (l == 0) maybe_verify(&job, nn[l], wout[l], w->idx, t);
            }
        } else {
            if (!eng->fn(mid, hi, lo0, MDS_ITERS, out, &g_abort_seq, abort_seq)) {
                w->aborted++; w->lost_s += now_s() - t0;
                continue;
            }
            w->batches++; w->nonces += lanes;
            double t = now_s();
            for (int l = 0; l < lanes; l++) {
                uint8_t hb[32]; hash_bytes(out + 8 * l, hb);
                uint64_t nonce = (uint64_t)hi << 32 | (uint32_t)(lo0 + l);
                if (hash_lt(hb, job.target)) { w->found++; push_cand(job.seq, nonce, hb, w->idx); }
                if (l == 0) maybe_verify(&job, nonce, hb, w->idx, t);
            }
        }
    }
    pad_free(pads);
    w->alive = 0;
    return NULL;
}

static void start_workers(int n)
{
    w_quit = 0; nworkers = n;
    for (int i = 0; i < n; i++) {
        worker_t *w = &workers[i]; memset(w, 0, sizeof *w); w->idx = i;
        w->started = pthread_create(&w->th, NULL, worker_thread, w) == 0;
    }
}
static void stop_workers(void)
{
    w_quit = 1;
    pthread_mutex_lock(&job_mx); g_abort_seq++; pthread_mutex_unlock(&job_mx);
    for (int i = 0; i < nworkers; i++) if (workers[i].started) pthread_join(workers[i].th, NULL);
    nworkers = 0;
}
static double workers_nonces(void) { double s = 0; for (int i = 0; i < nworkers; i++) s += workers[i].nonces; return s; }

/* ============================================================== pool connection */
typedef struct {
    sock_t fd; int connected, tls;
    char host[256], port[16];
    char buf[262144]; int bufn;
#ifndef NO_TLS
    mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context drbg; mbedtls_entropy_context ent; mbedtls_x509_crt ca;
    int tls_init;
#endif
} conn_t;

static conn_t pool;
static int cur_pool;

static int parse_url(const char *url, conn_t *c)
{
    const char *p = strstr(url, "://");
    c->tls = (strncmp(url, "stratum+ssl", 11) == 0 || strncmp(url, "stratum+tls", 11) == 0 ||
              strncmp(url, "ssl://", 6) == 0 || strncmp(url, "tls://", 6) == 0);
    p = p ? p + 3 : url;
    const char *colon = strrchr(p, ':');
    if (!colon) return -1;
    snprintf(c->host, sizeof c->host, "%.*s", (int)(colon - p), p);
    snprintf(c->port, sizeof c->port, "%s", colon + 1);
    return 0;
}

static void conn_close(conn_t *c)
{
#ifndef NO_TLS
    if (c->tls && c->tls_init) {
        if (c->fd != SOCK_INVALID) mbedtls_ssl_close_notify(&c->ssl);
        mbedtls_ssl_free(&c->ssl); mbedtls_ssl_config_free(&c->conf);
        mbedtls_ctr_drbg_free(&c->drbg); mbedtls_entropy_free(&c->ent); mbedtls_x509_crt_free(&c->ca);
        c->tls_init = 0;
    }
#endif
    if (c->fd != SOCK_INVALID) sock_close(c->fd);
    c->fd = SOCK_INVALID; c->connected = 0; c->bufn = 0;
}

static sock_t connect_one(struct addrinfo *ai)
{
    sock_t fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd == SOCK_INVALID) return SOCK_INVALID;
    sock_set_nonblock(fd, 1);
    int r = connect(fd, ai->ai_addr, (int)ai->ai_addrlen);
    if (r < 0 && (sock_errno() == SOCK_EINPROGRESS || sock_errno() == SOCK_EWOULDBLOCK)) {
        sock_pollfd p; memset(&p, 0, sizeof p); p.fd = fd; p.events = POLLOUT;
        int err = 0; socklen_t el = sizeof err;
        if (sock_poll(&p, 1, 10000) == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &el) == 0 && err == 0) r = 0;
    }
    if (r != 0) { sock_close(fd); return SOCK_INVALID; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    return fd;
}

static sock_t tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM;
    int gr = getaddrinfo(host, port, &hints, &res);
    if (gr != 0) { logm("pool: cannot resolve %s: %s", host, gai_strerror(gr)); return SOCK_INVALID; }
    sock_t fd = SOCK_INVALID;
    for (int pass = 0; pass < 2 && fd == SOCK_INVALID; pass++)
        for (ai = res; ai && fd == SOCK_INVALID; ai = ai->ai_next) {
            if ((pass == 0) != (ai->ai_family == AF_INET)) continue;
            char ip[64] = "";
            getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen, ip, sizeof ip, NULL, 0, NI_NUMERICHOST);
            fd = connect_one(ai);
            if (fd == SOCK_INVALID) logm("pool: no TCP connection to %s (%s)", ip, host);
            else if (opt.verbose) logm("pool: TCP connected to %s", ip);
        }
    freeaddrinfo(res);
    return fd;
}

#ifndef NO_TLS
static int bio_send(void *ctx, const unsigned char *b, size_t n)
{
    conn_t *c = (conn_t *)ctx;
    int w = (int)send(c->fd, (const char *)b, (int)n, MSG_NOSIGNAL);
    if (w < 0) return (sock_errno() == SOCK_EWOULDBLOCK || sock_errno() == SOCK_EINTR) ? MBEDTLS_ERR_SSL_WANT_WRITE : MBEDTLS_ERR_NET_SEND_FAILED;
    return w;
}
static int bio_recv(void *ctx, unsigned char *b, size_t n)
{
    conn_t *c = (conn_t *)ctx;
    int r = (int)recv(c->fd, (char *)b, (int)n, 0);
    if (r < 0) return (sock_errno() == SOCK_EWOULDBLOCK || sock_errno() == SOCK_EINTR) ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_NET_RECV_FAILED;
    if (r == 0) return MBEDTLS_ERR_NET_CONN_RESET;
    return r;
}
#endif

static int conn_open(conn_t *c, const char *url)
{
    conn_close(c);
    if (parse_url(url, c) < 0) { logm("pool: bad url %s", url); return -1; }
    c->fd = tcp_connect(c->host, c->port);
    if (c->fd == SOCK_INVALID) return -1;
    if (!c->tls) { c->connected = 1; return 0; }
#ifdef NO_TLS
    logm("pool: this build has no TLS support"); conn_close(c); return -1;
#else
    int ret;
    mbedtls_ssl_init(&c->ssl); mbedtls_ssl_config_init(&c->conf);
    mbedtls_ctr_drbg_init(&c->drbg); mbedtls_entropy_init(&c->ent); mbedtls_x509_crt_init(&c->ca);
    c->tls_init = 1;
    if ((ret = mbedtls_ctr_drbg_seed(&c->drbg, mbedtls_entropy_func, &c->ent, (const unsigned char *)"mds-cpu", 7)) != 0) goto fail;
    if ((ret = mbedtls_x509_crt_parse(&c->ca, (const unsigned char *)CA_BUNDLE, sizeof CA_BUNDLE)) < 0) goto fail;
    if ((ret = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) goto fail;
    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca, NULL);
    mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->drbg);
    if ((ret = mbedtls_ssl_setup(&c->ssl, &c->conf)) != 0) goto fail;
    if ((ret = mbedtls_ssl_set_hostname(&c->ssl, c->host)) != 0) goto fail;
    mbedtls_ssl_set_bio(&c->ssl, c, bio_send, bio_recv, NULL);
    {
        double th = now_s();
        while ((ret = mbedtls_ssl_handshake(&c->ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) goto fail;
            if (now_s() - th > 20) { logm("pool: TLS handshake timed out"); ret = MBEDTLS_ERR_SSL_TIMEOUT; goto fail; }
            sock_pollfd p; memset(&p, 0, sizeof p); p.fd = c->fd; p.events = ret == MBEDTLS_ERR_SSL_WANT_READ ? POLLIN : POLLOUT;
            sock_poll(&p, 1, 100);
        }
    }
    {
        const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&c->ssl);
        char fp[65] = "";
        if (peer) { unsigned char h[32]; mbedtls_sha256(peer->raw.p, peer->raw.len, h, 0); hex_of(h, 32, fp); }
        uint32_t vf = mbedtls_ssl_get_verify_result(&c->ssl);
        if (vf == 0) logm("pool: TLS ok (certificate verified, sha256 %.16s...)", fp);
        else {
            char vb[256]; mbedtls_x509_crt_verify_info(vb, sizeof vb, "", vf);
            for (char *q = vb; *q; q++) if (*q == '\n') *q = ' ';
            if (opt.insecure) logm("pool: certificate NOT verified (%s) - accepted because of --insecure (sha256 %s)", vb, fp);
            else { logm("pool: certificate not verified: %s(sha256 %s). Use --insecure to accept it.", vb, fp); conn_close(c); return -1; }
        }
    }
    c->connected = 1;
    return 0;
fail:
    { char e[160]; mbedtls_strerror(ret, e, sizeof e); logm("pool: TLS error: %s", e); }
    conn_close(c);
    return -1;
#endif
}

static int conn_send(conn_t *c, const char *s)
{
    int n = (int)strlen(s); const unsigned char *p = (const unsigned char *)s; double t0 = now_s();
    while (n > 0) {
        int w;
#ifndef NO_TLS
        if (c->tls) {
            w = mbedtls_ssl_write(&c->ssl, p, n);
            if (w == MBEDTLS_ERR_SSL_WANT_READ || w == MBEDTLS_ERR_SSL_WANT_WRITE) w = 0; else if (w < 0) return -1;
        } else
#endif
        {
            w = (int)send(c->fd, (const char *)p, n, MSG_NOSIGNAL);
            if (w < 0 && (sock_errno() == SOCK_EWOULDBLOCK || sock_errno() == SOCK_EINTR)) w = 0; else if (w < 0) return -1;
        }
        if (w == 0) {
            if (now_s() - t0 > 15) return -1;
            sock_pollfd pf; memset(&pf, 0, sizeof pf); pf.fd = c->fd; pf.events = POLLOUT; sock_poll(&pf, 1, 50);
        }
        p += w; n -= w;
    }
    return 0;
}

/* read what is available; -1 when the connection is gone */
static int conn_read(conn_t *c)
{
    for (;;) {
        if (c->bufn >= (int)sizeof c->buf - 1) c->bufn = 0;
        int r;
#ifndef NO_TLS
        if (c->tls) {
            r = mbedtls_ssl_read(&c->ssl, (unsigned char *)c->buf + c->bufn, sizeof c->buf - 1 - c->bufn);
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
            if (r <= 0) return -1;
        } else
#endif
        {
            r = (int)recv(c->fd, c->buf + c->bufn, (int)(sizeof c->buf - 1 - c->bufn), 0);
            if (r < 0 && (sock_errno() == SOCK_EWOULDBLOCK || sock_errno() == SOCK_EINTR)) return 0;
            if (r <= 0) return -1;
        }
        c->bufn += r;
    }
}

static char *conn_line(conn_t *c)
{
    static char line[262144];
    for (int i = 0; i < c->bufn; i++) if (c->buf[i] == '\n') {
        memcpy(line, c->buf, i); line[i] = 0;
        memmove(c->buf, c->buf + i + 1, c->bufn - i - 1); c->bufn -= i + 1;
        return line;
    }
    return NULL;
}

/* wait up to ms for the socket to be readable */
static void conn_wait(conn_t *c, int ms)
{
    if (!c->connected) { sleep_ms(ms); return; }
#ifndef NO_TLS
    if (c->tls && mbedtls_ssl_get_bytes_avail(&c->ssl)) return;
#endif
    sock_pollfd p; memset(&p, 0, sizeof p); p.fd = c->fd; p.events = POLLIN;
    sock_poll(&p, 1, ms);
}

/* ============================================================== stratum */
/* dialect: 0 = classic stratum (mining.subscribe/authorize/notify/submit, Midstate reference pool)
            2 = LuckyPool: mining.auth, mining.notify {job_id, blob, extranonce, target}, mining.submit [worker, job_id, nonce_low_hex] */
static int dialect;
static int authorized, have_job;
static uint32_t job_seq;
static long accepted, rejected, stale, dups, share_limited;
static double t_start;
static int next_id = 10;
static int fee_mode; static double fee_next; static long fee_accepted;
#if FEE_PCT > 0
static double fee_end, fee_total;
#endif


typedef struct { int id; char job[96]; uint64_t nonce; int gpu; double t, retry_at; int tries, fee; double diff; uint32_t seq; } pend_t;
static pend_t pend[512]; static int npend;
/* recent jobs: shares of a job are still sent after a non-clean job replaces it */
#define JOB_HIST 16
static job_t job_hist[JOB_HIST]; static int njob_hist;
static uint32_t clean_seq;        /* seq of the last clean job: older work is stale */
static const job_t *hist_find(uint32_t seq)
{
    for (int i = 0; i < njob_hist; i++) if (job_hist[i].seq == seq) return &job_hist[i];
    return NULL;
}
static uint64_t seen[4096]; static int nseen;
static int seen_add(uint64_t n, uint32_t seq)
{
    n ^= (uint64_t)seq * 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < nseen; i++) if (seen[i] == n) return 0;
    if (nseen < 4096) seen[nseen++] = n; else seen[rnd64() % 4096] = n;
    return 1;
}

static const char *pool_user(void) { return fee_mode ? FEE_ADDR : opt.user; }
static const char *pool_pass(void) { return fee_mode ? FEE_MWB : opt.pass; }
static const char *worker_name(void)
{
    const char *u = pool_user(), *d = strrchr(u, '.');
    return d && d[1] ? d + 1 : opt.rig;
}

static void err_text(cJSON *e, char *out, int n)
{
    out[0] = 0;
    if (cJSON_IsString(e)) snprintf(out, n, "%s", e->valuestring);
    else if (cJSON_IsArray(e) && cJSON_IsString(cJSON_GetArrayItem(e, 1))) snprintf(out, n, "%s", cJSON_GetArrayItem(e, 1)->valuestring);
    else if (cJSON_IsObject(e) && cJSON_IsString(cJSON_GetObjectItem(e, "message"))) snprintf(out, n, "%s", cJSON_GetObjectItem(e, "message")->valuestring);
    else if (e && !cJSON_IsNull(e)) { char *t = cJSON_PrintUnformatted(e); snprintf(out, n, "%s", t ? t : "?"); free(t); }
}

/* job metadata from a pool's job object: height, and the proof of work if named.
   Fields that are absent leave j->height / j->walk as they were. */
static void job_meta(cJSON *jo, job_t *j)
{
    static const char *hk[] = { "height", "blockHeight", "block_height" };
    for (unsigned k = 0; k < 3; k++) {
        cJSON *h = cJSON_GetObjectItem(jo, hk[k]);
        if (cJSON_IsNumber(h)) { j->height = (long long)h->valuedouble; break; }
        if (cJSON_IsString(h) && *h->valuestring) { j->height = atoll(h->valuestring); break; }
    }
    if (j->height >= 0) j->walk = (unsigned long long)j->height >= opt.walk_height;
    static const char *pk[] = { "pow", "algo", "algorithm" };
    for (unsigned k = 0; k < 3; k++) {
        const char *v = cJSON_GetStringValue(cJSON_GetObjectItem(jo, pk[k]));
        if (!v) continue;
        if (ci_str(v, "walk")) j->walk = 1;
        else if (ci_str(v, "blake3") || ci_str(v, "chain")) j->walk = 0;
    }
}

static void start_job(job_t j)
{
    /* proof of work: --algo, else the job's height / pow field, else Midstate Walk (the chain
       ended at block 371,500) */
    if (opt.algo == 2) j.walk = 1;
    else if (opt.algo == 1) j.walk = 0;
    else if (j.walk < 0) j.walk = 1;
    {
        static int last = -1;
        if (j.walk != last) {
            if (j.height >= 0) logm("pool: job at height %lld -> %s", j.height, j.walk ? "Midstate Walk" : "BLAKE3 chain");
            else logm("pool: mining %s%s", j.walk ? "Midstate Walk" : "the BLAKE3 chain", opt.algo ? " (--algo)" : " (the pool does not say the height)");
            last = j.walk;
        }
    }
    pthread_mutex_lock(&job_mx);
    /* same mining hash and target = same work: the chains go on, only the job id to submit changes */
    int same = have_job && cur_job.seq && !memcmp(j.mid, cur_job.mid, 32) && !memcmp(j.target, cur_job.target, 32) &&
               j.prefix == cur_job.prefix && j.free_bits == cur_job.free_bits && j.walk == cur_job.walk;
    if (same) {
        if (strcmp(j.pool_job, cur_job.pool_job)) {
            if (opt.verbose) logm("pool: job %s has the same work as %s, continuing", j.pool_job, cur_job.pool_job);
            snprintf(cur_job.pool_job, sizeof cur_job.pool_job, "%s", j.pool_job);
            for (int i = 0; i < njob_hist; i++) if (job_hist[i].seq == cur_job.seq) job_hist[i] = cur_job;
        }
    } else {
        j.seq = ++job_seq; j.fee = fee_mode;
        if (cur_job.seq && j.walk != cur_job.walk) j.clean = 1;   /* other proof of work: drop the old work */
        if (j.clean || !clean_seq) { clean_seq = j.seq; nseen = 0; g_abort_seq++; }
        cur_job = j;
        if (njob_hist == JOB_HIST) { memmove(job_hist, job_hist + 1, (JOB_HIST - 1) * sizeof *job_hist); njob_hist--; }
        job_hist[njob_hist++] = j;
    }
    have_job = 1;
    pthread_mutex_unlock(&job_mx);
    if (same) return;
    if (j.clean || opt.verbose)
        logm("pool: job %s%s, share target %d bits (difficulty %.0f)", j.pool_job, j.clean ? "" : " (same block)", target_bits(j.target), diff_of(j.target));
}

static void clear_job(void)
{
    pthread_mutex_lock(&job_mx);
    memset(&cur_job, 0, sizeof cur_job); have_job = 0; job_seq++;   /* seq 0 = no job: GPUs stop */
    cur_job.seq = 0; clean_seq = job_seq + 1; njob_hist = 0; g_abort_seq++;
    pthread_mutex_unlock(&job_mx);
}

/* parse a 256-bit big-endian target from the forms seen on Midstate pools */
static int parse_target(const char *st, uint8_t out[32])
{
    if (!st) return -1;
    const char *q = st; if ((q[0] == '0') && (q[1] == 'x' || q[1] == 'X')) q += 2;
    int n = (int)strlen(q);
    if (n == 8 || n == 16) {
        /* xmrig-style compact target: little-endian 32/64-bit value of the top of the target */
        uint8_t b[8] = {0}; int nb2 = n / 2;
        if (hex_to(q, b, nb2)) return -1;
        uint64_t v = 0; for (int i = nb2 - 1; i >= 0; i--) v = (v << 8) | b[i];
        if (nb2 == 4) v <<= 32;
        memset(out, 0xFF, 32);
        for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
        return 0;
    }
    char t[65]; if (n > 64) n = 64;
    memcpy(t, q, n); for (int i = n; i < 64; i++) t[i] = '0'; t[64] = 0;
    return hex_to(t, out, 32);
}

static job_t lp_last; static int lp_have;
static int parse_lucky_job(cJSON *jo, const char *line)
{
    job_t j; if (lp_have) j = lp_last; else { memset(&j, 0, sizeof j); j.walk = -1; j.height = -1; }
    cJSON *jid = cJSON_GetObjectItem(jo, "job_id");
    if (!jid) jid = cJSON_GetObjectItem(jo, "jobId");
    if (cJSON_IsNumber(jid)) snprintf(j.pool_job, sizeof j.pool_job, "%.0f", jid->valuedouble);
    else if (cJSON_IsString(jid)) snprintf(j.pool_job, sizeof j.pool_job, "\"%.80s\"", jid->valuestring);
    else { logm("pool: job without job_id: %.300s", line); return -1; }
    static const char *hk[] = { "miningHash", "mining_hash", "midstate", "midState", "headerHash", "header_hash", "hash" };
    const char *mh = NULL;
    for (unsigned k = 0; k < sizeof hk / sizeof hk[0] && !mh; k++) {
        const char *v = cJSON_GetStringValue(cJSON_GetObjectItem(jo, hk[k]));
        if (v && strlen(v) == 64) mh = v;
    }
    /* LuckyPool Midstate: "blob" = mining_hash[32] || nonce_le8 with the low nonce bytes zero
       and the session extranonce in the last bytes */
    const char *blob = cJSON_GetStringValue(cJSON_GetObjectItem(jo, "blob"));
    char xn_from_blob[17] = "";
    const char *xn = cJSON_GetStringValue(cJSON_GetObjectItem(jo, "extranonce"));
    if (blob && strlen(blob) == 80) {
        static char mh_buf[65];
        if (!mh) { memcpy(mh_buf, blob, 64); mh_buf[64] = 0; mh = mh_buf; }
        int xl = xn ? (int)strlen(xn) : 8; if (xl < 2 || xl > 16 || xl & 1) xl = 8;
        memcpy(xn_from_blob, blob + 80 - xl, xl); xn_from_blob[xl] = 0;
        if (xn && !ci_eq(xn, xn_from_blob)) logm("pool: WARNING extranonce %s differs from the blob's %s - using the blob's", xn, xn_from_blob);
        xn = xn_from_blob;
    }
    if (mh && hex_to(mh, j.mid, 32)) mh = NULL;
    if (!mh && !lp_have) { logm("pool: job without a mining hash I recognise: %.300s", line); return -1; }
    const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(jo, "target"));
    if (!st) st = cJSON_GetStringValue(cJSON_GetObjectItem(jo, "shareTarget"));
    if (st) { if (parse_target(st, j.target)) { logm("pool: bad target %s", st); return -1; } }
    else if (!lp_have) { logm("pool: job without a target: %.300s", line); return -1; }
    if (xn && strlen(xn) >= 2 && strlen(xn) <= 16 && strlen(xn) % 2 == 0) {
        uint8_t b[8] = {0}; int n = (int)strlen(xn) / 2;
        hex_to(xn, b, n);
        uint64_t v = 0; for (int i = n - 1; i >= 0; i--) v = (v << 8) | b[i];   /* little-endian bytes of the nonce */
        j.prefix = v; j.free_bits = 64 - 8 * n;
    }
    cJSON *nb = cJSON_GetObjectItem(jo, "nonceBits");
    if (cJSON_IsNumber(nb) && nb->valueint > 0) j.free_bits = nb->valueint;
    if (j.free_bits <= 0) { j.free_bits = 64; j.prefix = 0; }
    if (j.free_bits < 32) { logm("pool: the pool leaves only %d free nonce bits, 32 are needed", j.free_bits); return -1; }
    j.clean = 1;
    {
        static const char *ck[] = { "clean", "cleanJobs", "clean_jobs" };
        for (unsigned k = 0; k < 3; k++) { cJSON *c = cJSON_GetObjectItem(jo, ck[k]); if (c) { j.clean = cJSON_IsFalse(c) ? 0 : 1; break; } }
    }
    job_meta(jo, &j);
    lp_last = j; lp_have = 1;
    start_job(j);
    return 0;
}

static int send_submit(pend_t *p)
{
    char msg[512];
    p->id = next_id++;
    if (dialect == 2) {
        /* the pool rebuilds the 8-byte nonce as our low bytes || its extranonce */
        int nb = cur_job.free_bits >= 64 ? 8 : cur_job.free_bits / 8;
        uint8_t b[8]; char lh[17];
        for (int i = 0; i < nb; i++) b[i] = (uint8_t)(p->nonce >> (8 * i));
        hex_of(b, nb, lh);
        snprintf(msg, sizeof msg, "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",%s,\"%s\"]}\n", p->id, worker_name(), p->job, lh);
    } else {
        snprintf(msg, sizeof msg, "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",%s,%llu]}\n", p->id, worker_name(), p->job, (unsigned long long)p->nonce);
    }
    if (opt.pool_log) logm("pool -> %.*s", (int)strlen(msg) - 1, msg);
    p->t = now_s(); p->tries++;
    return conn_send(&pool, msg);
}

static void submit_cands(void)
{
    static cand_t local[1024]; int n;
    pthread_mutex_lock(&cand_mx); n = ncands; memcpy(local, cands, n * sizeof *cands); ncands = 0; pthread_mutex_unlock(&cand_mx);
    for (int i = 0; i < n; i++) {
        cand_t *c = &local[i];
        pthread_mutex_lock(&job_mx);
        const job_t *hj = have_job && c->seq >= clean_seq ? hist_find(c->seq) : NULL;
        job_t j; if (hj) j = *hj;
        pthread_mutex_unlock(&job_mx);
        if (!hj || !authorized || !pool.connected) { stale++; continue; }
        if (!hash_lt(c->hash, j.target)) { logm("T%d: candidate above the target?! (engine bug)", c->gpu); continue; }
        if (!seen_add(c->nonce, c->seq)) { dups++; continue; }
        if (opt.share_rate > 0) {
            /* a pool that starts a fast miner at a low difficulty gets tens of shares a second and
               may ban the address (LuckyPool, Walk): send at most share_rate per second (bucket of
               5), drop the rest; the pool's vardiff then raises the difficulty */
            static double tokens = 5, tlast;
            double t = now_s();
            if (tlast > 0) tokens += (t - tlast) * opt.share_rate;
            if (tokens > 5) tokens = 5;
            tlast = t;
            if (tokens < 1) { share_limited++; continue; }
            tokens -= 1;
        }
        if (npend >= 512) { logm("pool: too many shares waiting for an answer - dropping one"); stale++; continue; }
        pend_t *p = &pend[npend++];
        memset(p, 0, sizeof *p);
        snprintf(p->job, sizeof p->job, "%s", j.pool_job);
        p->nonce = c->nonce; p->gpu = c->gpu; p->fee = j.fee; p->diff = diff_of(j.target); p->seq = c->seq;
        if (send_submit(p) < 0) { logm("pool: send failed"); npend--; }
    }
}

static void send_login(void)
{
    char msg[800], user[400];
    if (dialect == 2) {
        /* Midstate LuckyPool: mining.auth ["<MSS-address>[=<diff>][.<worker>]", pass, agent] */
        if (strchr(pool_user(), '.')) snprintf(user, sizeof user, "%s", pool_user());
        else snprintf(user, sizeof user, "%s.%s", pool_user(), opt.rig);
        snprintf(msg, sizeof msg, "{\"id\":4,\"method\":\"mining.auth\",\"params\":[\"%s\",\"%s\",\"mds-cpu/%s\"]}\n", user, pool_pass(), VERSION);
        if (opt.pool_log || !fee_mode) logm("pool -> %.*s", (int)strlen(msg) - 1, msg);
        conn_send(&pool, msg);
    } else {
        snprintf(msg, sizeof msg, "{\"id\":3,\"method\":\"mining.subscribe\",\"params\":[\"mds-cpu/%s\"]}\n", VERSION);
        conn_send(&pool, msg);
        /* midstate pool (ciphernom/midstate pool.rs): [address, worker, midwimble address (optional,
           merged mining)]. "ADDRESS.worker" is split: the pool parses the address alone and refuses
           "ADDRESS.worker" with "Invalid Address". The midwimble address is --midwimble, else the
           pool password unless it is empty or "x". */
        char addr[400], wk[64];
        snprintf(addr, sizeof addr, "%s", pool_user());
        char *dot = strchr(addr, '.');
        if (dot) { *dot = 0; snprintf(wk, sizeof wk, "%s", dot[1] ? dot + 1 : opt.rig); } else snprintf(wk, sizeof wk, "%s", opt.rig);
        const char *mw = fee_mode ? FEE_MWB : (opt.midwimble && *opt.midwimble ? opt.midwimble :
                         (pool_pass() && *pool_pass() && strcmp(pool_pass(), "x") ? pool_pass() : ""));
        if (mw[0]) snprintf(msg, sizeof msg, "{\"id\":1,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\",\"%s\"]}\n", addr, wk, mw);
        else snprintf(msg, sizeof msg, "{\"id\":1,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n", addr, wk);
        if (opt.pool_log || !fee_mode) logm("pool -> %.*s", (int)strlen(msg) - 1, msg);
        if (mw[0] && !fee_mode) logm("pool: midwimble address %.20s... sent with the login (merged mining)", mw);
        conn_send(&pool, msg);
    }
}

static void handle_pool_line(const char *line)
{
    static int nlogged;
    if (opt.pool_log || nlogged < 12) { nlogged++; logm("pool <- %.600s", line); }
    cJSON *m = cJSON_Parse(line);
    if (!m) { logm("pool: unparsable line: %.120s", line); return; }
    cJSON *meth = cJSON_GetObjectItem(m, "method");
    cJSON *idj = cJSON_GetObjectItem(m, "id");
    int id = cJSON_IsNumber(idj) ? idj->valueint : -1;
    if (cJSON_IsString(meth)) {
        cJSON *params = cJSON_GetObjectItem(m, "params");
        const char *mn = meth->valuestring;
        if (!strcmp(mn, "mining.notify") && cJSON_IsObject(params)) parse_lucky_job(params, line);
        else if (!strcmp(mn, "mining.notify") && cJSON_IsArray(params) && cJSON_IsObject(cJSON_GetArrayItem(params, 0))) parse_lucky_job(cJSON_GetArrayItem(params, 0), line);
        else if (!strcmp(mn, "mining.notify") && cJSON_IsArray(params)) {
            /* reference pool: [job_id, mining_hash hex, batch_template, share_target hex] */
            cJSON *jid = cJSON_GetArrayItem(params, 0);
            const char *mh = cJSON_GetStringValue(cJSON_GetArrayItem(params, 1));
            const char *st = cJSON_GetStringValue(cJSON_GetArrayItem(params, 3));
            job_t j; memset(&j, 0, sizeof j); j.free_bits = 64; j.walk = -1; j.height = -1;
            cJSON *hp = cJSON_GetArrayItem(params, 4);   /* midstate >= v6.0.0: the job's height */
            if (cJSON_IsNumber(hp)) { j.height = (long long)hp->valuedouble; j.walk = (unsigned long long)j.height >= opt.walk_height; }
            if (cJSON_IsObject(cJSON_GetArrayItem(params, 2))) job_meta(cJSON_GetArrayItem(params, 2), &j);
            if (!(cJSON_IsNumber(jid) || cJSON_IsString(jid)) || hex_to(mh, j.mid, 32) || parse_target(st, j.target)) {
                logm("pool: mining.notify in a format this miner does not know: %.300s", line); goto out;
            }
            if (cJSON_IsNumber(jid)) snprintf(j.pool_job, sizeof j.pool_job, "%.0f", jid->valuedouble);
            else snprintf(j.pool_job, sizeof j.pool_job, "\"%.80s\"", jid->valuestring);
            j.clean = 1;
            start_job(j);
        } else if (!strcmp(mn, "job") && cJSON_IsObject(params)) {
            cJSON *jo = cJSON_GetObjectItem(params, "job");
            parse_lucky_job(cJSON_IsObject(jo) ? jo : params, line);
        } else if (!strcmp(mn, "mining.set_target") || !strcmp(mn, "mining.set_difficulty")) {
            logm("pool: %s ignored (the job's own target is used)", mn);
        } else if (!strcmp(mn, "client.reconnect")) {
            logm("pool: reconnect requested"); conn_close(&pool);
        }
        goto out;
    }
    char et[256]; err_text(cJSON_GetObjectItem(m, "error"), et, sizeof et);
    if (id == 3) {
        if (ci_str(et, "not supported") && dialect == 0) {
            logm("pool: stratum methods not supported - trying the LuckyPool dialect");
            dialect = 2; send_login();
        }
    } else if (id == 4) {
        cJSON *res = cJSON_GetObjectItem(m, "result");
        if (!et[0] && res && !cJSON_IsFalse(res) && !cJSON_IsNull(res)) {
            authorized = 1; logm("pool: authorized as %s, waiting for jobs", pool_user());
            cJSON *jo = cJSON_IsObject(res) ? cJSON_GetObjectItem(res, "job") : NULL;
            if (cJSON_IsObject(jo)) parse_lucky_job(jo, line);
        } else {
            logm("pool: authorization refused: %s", et[0] ? et : "result false");
            conn_close(&pool);
        }
    } else if (id == 1) {
        if (cJSON_IsTrue(cJSON_GetObjectItem(m, "result"))) { authorized = 1; logm("pool: authorized as %s (worker %s)", pool_user(), worker_name()); }
        else { logm("pool: authorization refused: %s - use a reusable MSS address (wallet generate-mss)", et[0] ? et : "?"); conn_close(&pool); }
    } else {
        for (int i = 0; i < npend; i++) if (pend[i].id == id) {
            pend_t *p = &pend[i];
            const char *es = et[0] ? et : NULL;
            cJSON *res = cJSON_GetObjectItem(m, "result");
            cJSON *stj = res ? cJSON_GetObjectItem(res, "status") : NULL;
            int ok = !es && (cJSON_IsTrue(res) || (cJSON_IsString(stj) && ci_eq(stj->valuestring, "OK")));
            if (ok && p->fee) { fee_accepted++; if (opt.pool_log) logm("devfee share accepted (%ld so far)", fee_accepted); }
            else if (ok) {
                accepted++;
                logm("share accepted [%ld/%ld] T%d, diff %.0f, %.2f s", accepted, accepted + rejected, p->gpu, p->diff, now_s() - p->t);
            } else if (es && ci_str(es, "busy")) {
                if (p->tries < 20) { p->retry_at = now_s() + 0.5 * p->tries; p->id = -1; break; }
                rejected++; logm("share dropped: pool verifier busy 20 times");
            } else {
                if (es && ci_str(es, "stale")) stale++;
                else if (es && ci_str(es, "duplicate")) dups++;
                else rejected++;
                logm("share rejected: %s (T%d, nonce %016llx)", es ? es : "?", p->gpu, (unsigned long long)p->nonce);
            }
            pend[i] = pend[--npend];
            break;
        }
    }
out:
    cJSON_Delete(m);
}

static void retry_pending(void)
{
    double t = now_s();
    for (int i = 0; i < npend; i++) {
        pend_t *p = &pend[i];
        if (p->id == -1 && t >= p->retry_at) {
            if (p->seq < clean_seq) { stale++; pend[i--] = pend[--npend]; continue; }
            send_submit(p);
        } else if (p->id > 0 && t - p->t > 120) {
            logm("share: no answer from the pool after 120 s");
            pend[i--] = pend[--npend];
        }
    }
}

/* ------------------------------------------------------------------ dev fee */
static void fee_drop(void) { conn_close(&pool); clear_job(); authorized = 0; npend = 0; }
static void fee_tick(void)
{
#if FEE_PCT > 0
    double t = now_s();
    if (!fee_mode) {
        if (t >= fee_next && pool.connected && authorized && have_job) {
            fee_mode = 1; fee_end = t + FEE_SECS;
            if (opt.pool_log) logm("devfee: mining %.0f s for %.16s...", FEE_SECS, FEE_ADDR);
            fee_drop();
        }
    } else if (t >= fee_end || (!authorized && t - (fee_end - FEE_SECS) > 60)) {
        fee_total += FEE_SECS; fee_mode = 0; fee_next = t + FEE_CYCLE - FEE_SECS;
        if (opt.pool_log) logm("devfee: window done, back to %s", opt.user);
        fee_drop();
    }
#endif
}

/* ------------------------------------------------------------------ stats */
static void log_huge(void);
static void print_stats(void)
{
    static int told_huge;
    if (!told_huge && nworkers && huge_ok_count + huge_fail_count >= nworkers) { told_huge = 1; log_huge(); }
    static double t_last, n_last, lost_last; static long jobs_last, clean_last;
    double t = now_s(), dt = t_last ? t - t_last : t - t_start;
    double n = workers_nonces(), lost = 0; long jobs = 0, cleanj = 0; int dead = 0;
    for (int i = 0; i < nworkers; i++) { lost += workers[i].lost_s; dead += !workers[i].alive; }
    if (nworkers) { jobs = workers[0].jobs; cleanj = workers[0].jobs_clean; }
    double r = dt > 0 ? (n - n_last) / dt : 0, el = t - t_start;
    int walk; pthread_mutex_lock(&job_mx); walk = cur_job.seq ? cur_job.walk : -1; pthread_mutex_unlock(&job_mx);
    char lim[64] = "";
    if (share_limited) snprintf(lim, sizeof lim, ", %ld held back", share_limited);
    logm("%s %.3f kH/s (%.0f H/s, avg %.0f H/s, %d threads%s) | shares %ld/%ld/%ld (acc/rej/stale%s) | jobs %ld (%ld new blocks), %.2f s lost | errors %ld | up %.0f min",
         walk == 1 ? "Walk" : walk == 0 ? "chain" : "idle", r / 1000.0, r, el > 0 ? n / el : 0, nworkers, dead ? " SOME STOPPED" : "",
         accepted, rejected, stale, lim, jobs - jobs_last, cleanj - clean_last, nworkers ? (lost - lost_last) / nworkers : 0, ver_bad, el / 60.0);
    if (opt.verbose) { long ab = 0; for (int i = 0; i < nworkers; i++) ab += workers[i].aborted; logm("batches dropped on new blocks so far: %ld", ab); }
    t_last = t; n_last = n; lost_last = lost; jobs_last = jobs; clean_last = cleanj;
}

/* ------------------------------------------------------------------ pool loop */
static void run_pool(void)
{
    double t_rx = now_s(), t_conn = 0, t_stats = now_s();
    int pi = 0, backoff = 2;
    t_start = now_s();
#if FEE_PCT > 0
    fee_next = now_s() + FEE_CYCLE * 0.05 + (double)(rnd64() % (uint64_t)(FEE_CYCLE * 0.9));
    logm("dev fee: %d%% of the mining time (%.0f s every %.0f min) to %s, with its merged-mined midwimble to %.20s...", FEE_PCT, FEE_SECS, FEE_CYCLE / 60, FEE_ADDR, FEE_MWB);
#endif
    while (!g_stop) {
        if (!pool.connected) {
            if (now_s() - t_conn < backoff) { sleep_ms(100); if (now_s() - t_stats >= opt.stats_s) { print_stats(); t_stats = now_s(); } continue; }
            cur_pool = pi % opt.npools;
            const char *url = opt.pools[cur_pool];
            logm("pool: connecting to %s%s", url, fee_mode ? " (devfee)" : "");
            t_conn = now_s();
            if (conn_open(&pool, url) < 0) {
                if (fee_mode) { fee_mode = 0; fee_next = now_s() + FEE_CYCLE; continue; }
                logm("pool: cannot connect to %s, retrying in %d s", url, backoff);
                backoff = backoff * 2 > 60 ? 60 : backoff * 2; pi++;
                continue;
            }
            backoff = 2; t_rx = now_s(); authorized = 0; npend = 0; lp_have = 0;
            if (opt.dialect >= 0) dialect = opt.dialect;
            else dialect = (ci_str(pool.host, "lproute") || ci_str(pool.host, "luckypool")) ? 2 : 0;
            logm("pool: using the %s dialect", dialect == 2 ? "LuckyPool" : "classic stratum");
            send_login();
        }
        conn_wait(&pool, 50);
        if (conn_read(&pool) < 0) { logm("pool: connection lost"); conn_close(&pool); }
        else { char *line; while ((line = conn_line(&pool)) != NULL) { t_rx = now_s(); handle_pool_line(line); } }
        if (!pool.connected) {
            clear_job(); authorized = 0;
            if (fee_mode) { fee_mode = 0; fee_next = now_s() + FEE_CYCLE; continue; }
            pi++;
            continue;
        }
        submit_cands();
        fee_tick();
        if (!pool.connected) continue;
        retry_pending();
        if (now_s() - t_rx > 300) { logm("pool: nothing received for 300 s - reconnecting"); conn_close(&pool); continue; }
        if (cur_pool != 0 && !fee_mode && opt.failback_s > 0 && now_s() - t_conn > opt.failback_s) {
            /* on a fallback pool for --failback s (15 min): try the first pool again (we come back here if it fails) */
            logm("pool: trying the first pool %s again", opt.pools[0]);
            conn_close(&pool); clear_job(); pi = 0; t_conn = 0; continue;
        }
        if (now_s() - t_stats >= opt.stats_s) { print_stats(); t_stats = now_s(); }
    }
}

/* ============================================================== test / bench / tune */
/* full-chain vectors of the reference implementation (midstate extension.rs):
   midstate, nonce as 8 big-endian bytes, x_1000000 */
static const char *kat[][3] = {
    { "a65a5425fe56901392306a7814b583f07744160b9ae8077aee6e11391314ff87", "ccb205dfe78a7f06", "605aa059e73984696afad7d79b550cb7c37ead102011ed3d5cc736d7d5b296fe" },
    { "39329a365f0d27a3a6db1a093ed93a758085e1c1d7bdfe2e2e87f9d9fc15b0a5", "b006943056a9a27d", "60ec5a586d3994e21ab4aaff7c29be294cfdc1cd6e9839f1297069277678f0ff" },
};

static int run_tests_chain(void)
{
    int fails = 0;
    uint8_t mid[2][32], nb[8], exp[2][32]; uint64_t nonce[2];
    for (int v = 0; v < 2; v++) {
        hex_to(kat[v][0], mid[v], 32); hex_to(kat[v][1], nb, 8); hex_to(kat[v][2], exp[v], 32);
        nonce[v] = 0; for (int i = 0; i < 8; i++) nonce[v] = nonce[v] << 8 | nb[i];
    }
    {   /* the scalar reference itself */
        uint32_t h[8]; uint8_t b[32]; cpu_chain(mid[0], nonce[0], MDS_ITERS, h); hash_bytes(h, b);
        int ok = !memcmp(b, exp[0], 32); fails += !ok;
        logm("TEST chain reference code, known full-chain vector: %s", ok ? "OK" : "FAIL");
    }
    for (int e = NENGINES - 1; e >= 0; e--) {
        const engine_t *E = &engines[e];
        if (!isa_ok(E->isa)) continue;
        int bad = 0; uint32_t out[MAX_LANES * 8], m[8];
        uint8_t rm[32]; for (int i = 0; i < 32; i++) rm[i] = (uint8_t)rnd64();
        for (int i = 0; i < 8; i++) m[i] = le32(rm + 4 * i);
        uint32_t hi = (uint32_t)rnd64(), lo = (uint32_t)rnd64() & 0x00FFFFFFu;
        E->fn(m, hi, lo, 1000, out, NULL, 0);
        for (int l = 0; l < E->lanes; l++) {
            uint32_t h[8]; cpu_chain(rm, (uint64_t)hi << 32 | (uint32_t)(lo + l), 1000, h);
            if (memcmp(h, out + 8 * l, 32)) bad++;
        }
        int lane = E->lanes - 1;
        for (int i = 0; i < 8; i++) m[i] = le32(mid[1] + 4 * i);
        E->fn(m, (uint32_t)(nonce[1] >> 32), (uint32_t)nonce[1] - (uint32_t)lane, MDS_ITERS, out, NULL, 0);
        uint8_t b[32]; hash_bytes(out + 8 * lane, b);
        if (memcmp(b, exp[1], 32)) bad++;
        logm("TEST chain %-10s: %s", E->name, bad ? "FAIL" : "OK");
        fails += bad != 0;
    }
    return fails;
}

/* Midstate Walk known answers (walk.rs GOLDEN) */
static const char *walk_golden[3][3] = {
    { "0000000000000000000000000000000000000000000000000000000000000000", "0", "a934fced2d9a53fb09d6abe089f3d2f5bba9a421b41ee5726233a525cc7438e7" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "18446744073709551615", "65d237f595f07bee156c635ad45f721987ce38d79ea14c89e40c5555613d0768" },
    { "374bf98b3b8f7f41a9e291154fc582a65bb3e14180cb9a07fef08e55f3006c50", "42", "5f2da9d320de391aef28bcaab63e3d1a25402b4541cdff8680059a87c7d515b7" },
};

static int run_tests_walk(void)
{
    int fails = 0;
    int ok = walk_selftest(); fails += !ok;
    logm("TEST Walk reference code (walk_ref.c), 3 known answers: %s", ok ? "OK" : "FAIL");
    int huge; uint64_t *pads = pad_alloc((size_t)WALK_MAX_K * WALK_PAD_BYTES, &huge);
    for (int e = 0; e < NWALK; e++) {
        const walk_engine_t *E = &walk_engines[e];
        if (!walk_isa_ok(E->isa)) { logm("TEST Walk %-5s not supported by this CPU, skipped", E->name); continue; }
        int bad = 0; double t0 = now_s(); long walks = 0;
        for (int k = 1; k <= WALK_MAX_K; k++) {
            /* every known answer in one slot (rotating), the other slots against the reference */
            for (int g = 0; g < 3; g++) {
                uint8_t mh[32], want[32], out[WALK_MAX_K][32]; uint64_t nn[WALK_MAX_K];
                int slot = (g + k) % k;
                hex_to(walk_golden[g][0], mh, 32); hex_to(walk_golden[g][2], want, 32);
                uint64_t base = strtoull(walk_golden[g][1], NULL, 10);
                for (int i = 0; i < k; i++) nn[i] = base + (uint64_t)(i - slot) * 1000003ull;
                E->fn[k - 1](mh, nn, out, pads, NULL, 0); walks += k;
                if (memcmp(out[slot], want, 32)) bad++;
                if (g == 2) for (int i = 0; i < k; i++) if (i != slot) { uint8_t ref[32]; walk_hash(mh, nn[i], ref); if (memcmp(ref, out[i], 32)) bad++; }
            }
        }
        /* abort */
        { uint8_t mh[32] = {0}, out[WALK_MAX_K][32]; uint64_t nn[WALK_MAX_K] = {0}; volatile uint32_t sq = 5;
          if (E->fn[0](mh, nn, out, pads, &sq, 4) != 0) bad++; }
        double dt = now_s() - t0;
        logm("TEST Walk %-5s (%s): known answers in every slot with 1..%d walks per thread, other slots against the reference, abort: %s",
             E->name, E->desc, WALK_MAX_K, bad ? "FAIL" : "OK");
        (void)dt; (void)walks;
        fails += bad != 0;
    }
    pad_free(pads);
    return fails;
}

static int run_tests(void)
{
    int f = run_tests_walk();
    f += run_tests_chain();
    return f == 0;
}

static void set_bench_job(int walk)
{
    job_t j; memset(&j, 0, sizeof j);
    for (int i = 0; i < 32; i++) j.mid[i] = (uint8_t)rnd64();
    j.free_bits = 64; j.walk = walk; j.height = -1;   /* target 0: nothing is ever found */
    pthread_mutex_lock(&job_mx); j.seq = ++job_seq; cur_job = j; g_abort_seq++; pthread_mutex_unlock(&job_mx);
}

/* H/s with n threads; walk: engine we with k walks per thread, else chain engine e.
   Warm-up until every thread finished one batch, then secs. */
static double bench_run(int walk, const engine_t *e, const walk_engine_t *we, int k, int n, double secs)
{
    const engine_t *save = eng; const walk_engine_t *wsave = weng; int ksave = walk_k_eff; double save_v = opt.verify_s;
    if (e) eng = e;
    if (we) weng = we;
    if (k) walk_k_eff = k;
    opt.verify_s = 0;
    set_bench_job(walk);
    start_workers(n);
    double tw = now_s();
    for (;;) {
        int all = 1; for (int i = 0; i < n; i++) if (!workers[i].batches) all = 0;
        if (all || g_stop || now_s() - tw > 30) break;
        sleep_ms(10);
    }
    double n0 = workers_nonces(), t0 = now_s(), n1, t1;
    while (!g_stop && now_s() - t0 < secs) sleep_ms(50);
    n1 = workers_nonces(); t1 = now_s();
    stop_workers();
    pthread_mutex_lock(&job_mx); memset(&cur_job, 0, sizeof cur_job); pthread_mutex_unlock(&job_mx);
    eng = save; weng = wsave; walk_k_eff = ksave; opt.verify_s = save_v;
    return t1 > t0 ? (n1 - n0) / (t1 - t0) : 0;
}

/* ============================================================== exit */
static int finish(int code)
{
    g_stop = 1;
    fflush(stdout);
    if (log_fp) fflush(log_fp);
    g_exited = 1;
#ifdef _WIN32
    TerminateProcess(GetCurrentProcess(), (UINT)code);
#endif
    _exit(code);
    return code;
}

#ifdef _WIN32
static BOOL WINAPI on_console(DWORD ev)
{
    g_stop = 1;
    if (ev == CTRL_C_EVENT || ev == CTRL_BREAK_EVENT) return TRUE;   /* main loop exits and calls finish() */
    for (int i = 0; i < 30 && !g_exited; i++) Sleep(100);
    fflush(stdout);
    if (log_fp) fflush(log_fp);
    TerminateProcess(GetCurrentProcess(), 0);
    return TRUE;
}
#endif

/* ============================================================== main */
static void usage(void)
{
    printf("mds-cpu %s - Midstate (MDS) miner for x86-64 CPUs: Midstate Walk (from block 371,500) and the BLAKE3 chain\n\n"
           "  mds-cpu --pool URL --user ADDRESS[.worker] [options]\n"
           "  mds-cpu --test | --bench [SECONDS] | --tune [SECONDS]\n\n"
           "  --pool URL         stratum+ssl://host:port or stratum+tcp://host:port (repeat for failover)\n"
           "  --user ADDRESS     reusable MSS address (midstate wallet generate-mss), optionally .worker\n"
           "  --pass P           pool password (default x)\n"
           "  --rig NAME         worker name when --user has none (default cpu)\n"
           "  --threads N        mining threads (default: all logical CPUs)\n"
           "  --walk-k N         Walk: walks stepped in turn per thread, 1-6 (default: measured at start, 1-4)\n"
           "  --no-calibrate     Walk: skip that measurement (2 walks per thread with SMT threads, else 3)\n"
           "  --walk-engine E    Walk: auto (default), v3, aesni, soft\n"
           "  --no-huge-pages    Walk: do not use large pages for the scratchpads\n"
#ifdef _WIN32
           "  --setup-large-pages  give this user the \"Lock pages in memory\" right (administrator console, then sign out/in)\n"
#endif
           "  --algo auto|walk|chain  proof of work (default auto: from the job's height, Walk if the pool does not say)\n"
           "  --engine NAME      BLAKE3 chain engine: auto (default), avx512x2, avx512, avx512vlx2, avx512vl, avx2x2, avx2, sse2x2, sse2\n"
           "  --failback S       on a fallback pool, try the first --pool again after S seconds (default 900)\n"
           "  --share-rate N     most shares per second sent to the pool (default 2, 0 = no limit)\n"
           "  --midwimble ADDR   midwimble address for merged mining on a midstate pool (3rd authorize parameter;\n"
           "                     a --pass other than x is used the same way)\n"
           "  --priority 0-5     thread priority: 0 idle, 1 lowest (default), 2 below normal, 3 normal, 4, 5\n"
           "  --affinity         pin every thread to one logical CPU\n"
           "  --verify-s S       recompute one result with the reference code every S seconds (default 60, 0 = off)\n"
           "  --stats S          statistics line every S seconds (default 30)\n"
           "  --dialect 0|2      force classic stratum (0) or LuckyPool (2); default by host name\n"
           "  --insecure         accept a TLS certificate that does not verify\n"
           "  --pool-log         log every pool message\n"
           "  --log FILE         also write the log to FILE\n"
           "  --verbose\n", VERSION);
#if FEE_PCT > 0
    printf("\nThis build mines %d%% of the time for the developer (%s;\nmerged-mined midwimble of those windows to %s).\n", FEE_PCT, FEE_ADDR, FEE_MWB);
#endif
}

static void log_huge(void)
{
    if (huge_ok_count && !huge_fail_count) logm("scratchpads in large pages on all threads");
    else if (opt.huge && huge_fail_count) {
#ifdef _WIN32
        logm("large pages not available (%d of %d threads without): about 5-15%% slower. To enable them run setup_large_pages.bat once as administrator, then sign out and in again",
             huge_fail_count, huge_ok_count + huge_fail_count);
#else
        logm("transparent huge pages not available (%d threads): echo madvise > /sys/kernel/mm/transparent_hugepage/enabled", huge_fail_count);
#endif
    }
}

int main(int argc, char **argv)
{
    sock_init();
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
#ifdef _WIN32
    SetConsoleCtrlHandler(on_console, TRUE);
#else
    signal(SIGHUP, on_sig);
#endif
    double bench_s = 30, tune_s = 8; int tune = 0, setup_lp = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
#define NEEDV if (!v) { fprintf(stderr, "%s needs a value\n", a); return 2; } i++
        if (!strcmp(a, "--pool")) { NEEDV; if (opt.npools < 8) opt.pools[opt.npools++] = v; }
        else if (!strcmp(a, "--user")) { NEEDV; opt.user = v; }
        else if (!strcmp(a, "--pass")) { NEEDV; opt.pass = v; }
        else if (!strcmp(a, "--rig")) { NEEDV; opt.rig = v; }
        else if (!strcmp(a, "--threads") || !strcmp(a, "-t")) { NEEDV; opt.threads = atoi(v); }
        else if (!strcmp(a, "--engine")) { NEEDV; opt.engine = v; }
        else if (!strcmp(a, "--walk-k")) { NEEDV; opt.walk_k = atoi(v); }
        else if (!strcmp(a, "--walk-engine")) { NEEDV; opt.walk_isa = v; }
        else if (!strcmp(a, "--no-huge-pages")) opt.huge = 0;
        else if (!strcmp(a, "--no-calibrate")) opt.calibrate = 0;
        else if (!strcmp(a, "--failback")) { NEEDV; opt.failback_s = atof(v); }
        else if (!strcmp(a, "--setup-large-pages")) setup_lp = 1;
        else if (!strcmp(a, "--algo")) { NEEDV; opt.algo = ci_eq(v, "walk") ? 2 : ci_eq(v, "chain") || ci_eq(v, "blake3") ? 1 : 0; }
        else if (!strcmp(a, "--walk-height")) { NEEDV; opt.walk_height = strtoull(v, NULL, 10); }
        else if (!strcmp(a, "--share-rate")) { NEEDV; opt.share_rate = atof(v); }
        else if (!strcmp(a, "--midwimble")) { NEEDV; opt.midwimble = v; }
        else if (!strcmp(a, "--priority")) { NEEDV; opt.priority = atoi(v); }
        else if (!strcmp(a, "--affinity")) opt.affinity = 1;
        else if (!strcmp(a, "--verify-s")) { NEEDV; opt.verify_s = atof(v); }
        else if (!strcmp(a, "--stats")) { NEEDV; opt.stats_s = atof(v); }
        else if (!strcmp(a, "--dialect")) { NEEDV; opt.dialect = atoi(v); }
        else if (!strcmp(a, "--log")) { NEEDV; opt.log_file = v; }
        else if (!strcmp(a, "--bench")) { opt.bench = 1; if (v && v[0] != '-') { bench_s = atof(v); i++; } }
        else if (!strcmp(a, "--tune")) { tune = 1; if (v && v[0] != '-') { tune_s = atof(v); i++; } }
        else if (!strcmp(a, "--test")) opt.test = 1;
        else if (!strcmp(a, "--insecure")) opt.insecure = 1;
        else if (!strcmp(a, "--pool-log")) opt.pool_log = 1;
        else if (!strcmp(a, "--verbose")) opt.verbose = 1;
        else if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(); return 0; }
        else { fprintf(stderr, "unknown option %s\n", a); usage(); return 2; }
#undef NEEDV
    }
    if (opt.log_file) log_fp = fopen(opt.log_file, "a");
#ifdef _WIN32
    if (setup_lp) return setup_large_pages() ? 0 : 1;
#else
    if (setup_lp) { printf("--setup-large-pages is for Windows\n"); return 0; }
#endif
    if (!opt.bench && !opt.test && !tune && (!opt.npools || !opt.user)) { usage(); return 2; }
    logm("mds-cpu %s - Midstate CPU miner: Midstate Walk (H/s = attempts per second) and the BLAKE3 chain", VERSION);

    cpu_info();
    walk_init_all();
    if (opt.threads <= 0) opt.threads = n_logical;
    if (opt.threads > MAX_THREADS) opt.threads = MAX_THREADS;
    if (ci_eq(opt.engine, "auto")) eng = engine_auto();
    else {
        eng = engine_by_name(opt.engine);
        if (!eng) { logm("unknown engine %s", opt.engine); return 2; }
        if (!isa_ok(eng->isa)) { logm("engine %s is not supported by this CPU", eng->name); return 2; }
    }
    if (ci_eq(opt.walk_isa, "auto")) weng = walk_engine_auto();
    else {
        weng = NULL;
        for (int i = 0; i < NWALK; i++) if (ci_eq(opt.walk_isa, walk_engines[i].name)) weng = &walk_engines[i];
        if (!weng) { logm("unknown Walk engine %s", opt.walk_isa); return 2; }
        if (!walk_isa_ok(weng->isa)) { logm("Walk engine %s is not supported by this CPU", weng->name); return 2; }
    }
    if (opt.walk_k < 0 || opt.walk_k > WALK_MAX_K) { logm("--walk-k must be 1..%d", WALK_MAX_K); return 2; }
    walk_k_eff = opt.walk_k ? opt.walk_k : (opt.threads > n_cores ? 2 : 3);
    logm("CPU: %s, %d cores / %d threads; AES-NI %s, AVX2 %s, AVX-512 %s", cpu_brand, n_cores, n_logical,
         walk_isa_ok(WISA_AESNI) ? "yes" : "no", isa_ok(ISA_AVX2) ? "yes" : "no", isa_ok(ISA_AVX512) ? "yes" : "no");

    if (opt.test) {
        int ok = run_tests();
        logm(ok ? "TEST RESULT: ALL OK" : "TEST RESULT: FAILURES");
        return finish(ok ? 0 : 4);
    }
    if (tune && opt.algo == 1) {
        double best = 0; const engine_t *be = NULL; int bt = 0;
        logm("TUNE (BLAKE3 chain): every setting runs %.0f s (plus warm-up)", tune_s);
        for (int e = 0; e < NENGINES && !g_stop; e++) {
            if (!isa_ok(engines[e].isa)) continue;
            double r = bench_run(0, &engines[e], NULL, 0, n_logical, tune_s);
            logm("TUNE chain engine %-10s %d threads: %.0f H/s", engines[e].name, n_logical, r);
            if (r > best) { best = r; be = &engines[e]; bt = n_logical; }
        }
        if (be && n_cores != n_logical && !g_stop) {
            double r = bench_run(0, be, NULL, 0, n_cores, tune_s);
            logm("TUNE chain engine %-10s %d threads: %.0f H/s", be->name, n_cores, r);
            if (r > best) { best = r; bt = n_cores; }
        }
        if (be) logm("TUNE: best %.0f H/s with --algo chain --engine %s --threads %d", best, be->name, bt);
        return finish(0);
    }
    if (tune) {
        /* Walk: walks per thread x threads (logical, then physical cores) on the best engine,
           then the other engines at the best point */
        double best = 0; int bk = 0, bt = 0; const walk_engine_t *be = weng;
        int tcount[2] = { n_logical, n_cores }, nt = n_cores != n_logical ? 2 : 1;
        logm("TUNE (Midstate Walk): engine %s, every setting runs %.0f s", weng->name, tune_s);
        for (int ti = 0; ti < nt && !g_stop; ti++)
            for (int k = 1; k <= WALK_MAX_K && !g_stop; k++) {
                if ((size_t)k * tcount[ti] * WALK_PAD_BYTES > (size_t)3 << 30) continue;
                double r = bench_run(1, NULL, weng, k, tcount[ti], tune_s);
                logm("TUNE Walk %d threads x %d walks per thread: %.0f H/s", tcount[ti], k, r);
                if (r > best) { best = r; bk = k; bt = tcount[ti]; }
            }
        log_huge();
        for (int e = 0; e < NWALK && !g_stop; e++) {
            if (&walk_engines[e] == weng || !walk_isa_ok(walk_engines[e].isa) || walk_engines[e].isa == WISA_SOFT) continue;
            double r = bench_run(1, NULL, &walk_engines[e], bk, bt, tune_s);
            logm("TUNE Walk engine %s, %d threads x %d: %.0f H/s", walk_engines[e].name, bt, bk, r);
            if (r > best) { best = r; be = &walk_engines[e]; }
        }
        logm("TUNE: best %.0f H/s (%.2f kH/s) with --threads %d --walk-k %d --walk-engine %s", best, best / 1000, bt, bk, be->name);
        return finish(0);
    }
    if (opt.bench) {
        if (opt.algo == 1) {
            logm("BENCH BLAKE3 chain: engine %s (%s), %d threads, %.0f s", eng->name, eng->desc, opt.threads, bench_s);
            double r = bench_run(0, eng, NULL, 0, opt.threads, bench_s);
            logm("BENCH: %.0f H/s = %.3f kH/s (%.1f H/s per thread)", r, r / 1000, r / opt.threads);
        } else {
            logm("BENCH Midstate Walk: engine %s (%s), %d threads x %d walks per thread, %.0f s", weng->name, weng->desc, opt.threads, walk_k_eff, bench_s);
            double r = bench_run(1, NULL, weng, walk_k_eff, opt.threads, bench_s);
            log_huge();
            logm("BENCH: %.0f H/s = %.2f kH/s (%.1f H/s per thread)", r, r / 1000, r / opt.threads);
        }
        return finish(0);
    }

    if (!opt.walk_k && opt.calibrate && opt.algo != 1) {
        /* as midstate v6.5.0: time 1 to 4 walks per thread on all the mining threads (~10 s,
           once per run) and mine with the fastest; tune.bat also tries 5-6 and the thread count */
        char line[256]; int n = 0, bestk = walk_k_eff; double best = 0;
        logm("Walk: measuring 1 to 4 walks per thread on %d threads (about 10 s, skip with --walk-k N)", opt.threads);
        for (int k = 1; k <= 4 && !g_stop; k++) {
            double r = bench_run(1, NULL, weng, k, opt.threads, 2.0);
            n += snprintf(line + n, sizeof line - n, "%s%d: %.0f/s", k > 1 ? ", " : "", k, r);
            if (r > best) { best = r; bestk = k; }
        }
        walk_k_eff = bestk;
        logm("Walk: attempts with 1 to 4 walks per thread: %s; mining with %d", line, bestk);
        log_huge(); huge_ok_count = huge_fail_count = 0;
    }
    logm("mining with %d threads, priority %d%s; Walk: engine %s, %d walks per thread (%d KiB of scratchpad each); chain: engine %s",
         opt.threads, opt.priority, opt.affinity ? ", pinned" : "", weng->name, walk_k_eff, walk_k_eff * 256, eng->name);
    if (opt.share_rate > 0) logm("at most %.3g shares per second go to the pool (--share-rate)", opt.share_rate);
    pthread_t vth;
    pthread_create(&vth, NULL, verifier_thread, NULL);
    start_workers(opt.threads);
    pool.fd = SOCK_INVALID;
    run_pool();
    print_stats();
    g_stop = 1;
    stop_workers();
    pthread_join(vth, NULL);
    conn_close(&pool);
    logm("mds-cpu stopped");
    return finish(0);
}
