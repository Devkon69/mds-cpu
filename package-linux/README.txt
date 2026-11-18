mds-cpu 0.3.1 - Midstate (MDS) miner for x86-64 CPUs (Linux)
Source code: see the GitHub repository this package comes from (GPL v3).
===============================================================

Proof of work
  From block 371,500 Midstate uses Midstate Walk: every attempt seeds a private 256 KiB
  scratchpad with AES, then takes 2^18 dependent steps over it (four random reads and writes
  a step, 64-bit multiply / multiply-high / divide / AES round, a program per attempt that
  BLAKE3 redraws every 4,096 steps). It suits CPUs: the scratchpad lives in the core's L2.
  The miner reads the block height from each pool job and switches by itself; the old
  BLAKE3 chain (blocks below 371,500) is still built in. If a pool does not send the height
  the miner mines the Walk (--algo chain forces the old one).

  Unit: H/s = attempts per second.

Why it is fast
  One walk is a single dependent chain, so on its own it keeps a core waiting on its L2.
  mds-cpu steps several walks of different nonces in turn on every thread (--walk-k, 1-6),
  so the core overlaps them, with the step written for each walk separately (operation
  dispatch always predicted), AES-NI, and the scratchpads in large pages. --tune finds
  the best walks-per-thread and thread count for your CPU.

Requirements
  Any x86-64 Linux (the binary is static: no libraries needed), any x86-64 CPU (AES-NI
  strongly recommended). About 256 KiB of memory per walk.

Usage
  1. ./mds-cpu --test    -> must end with "TEST RESULT: ALL OK"
  2. ./mds-cpu --tune    -> optional (the miner already measures 1-4 walks per thread at every
                            start): prints the best "--threads N --walk-k K --walk-engine E"
  3. start_mds_cpu.sh: put your MSS address in USER_ADDR (reusable addresses only, made with
     "midstate wallet generate-mss"), a worker name in RIG, then  sh start_mds_cpu.sh
  Huge pages: the miner asks for transparent huge pages. If it prints "transparent huge pages
  not available", run as root:  echo madvise > /sys/kernel/mm/transparent_hugepage/enabled

Statistics line (every 30 s)
  Walk 14.250 kH/s (14250 H/s, avg 14180 H/s, 32 threads) | shares 120/0/0 (acc/rej/stale)
  | jobs 3 (1 new blocks), 0.00 s lost | errors 0 | up 42 min
    held back = shares not sent because of --share-rate (the pool raises the difficulty soon)
    errors    = results that did not match the reference code (checked every 60 s): if this
                is not 0 your CPU is unstable (overclock, undervolt, Curve Optimizer too low)

Options
  --threads N         mining threads (default: all logical CPUs)
  --walk-k N          walks stepped in turn per thread, 1-6. Default: measured at start (1 to 4,
                      about 10 s, once per run) and the fastest is used; --no-calibrate skips it
  --walk-engine E     auto, v3 (AES-NI + AVX2), aesni, soft (no AES-NI)
  --no-huge-pages     do not try large pages
  --share-rate N      most shares per second sent to the pool (default 2, 0 = no limit): a pool
                      that starts a fast miner at a low difficulty may ban the address otherwise
  --midwimble ADDR    midwimble address for merged mining on a midstate pool (sent as the 3rd
                      mining.authorize parameter); a --pass other than x is used the same way
  --algo auto|walk|chain   proof of work (default auto, from the job's height)
  --engine NAME       BLAKE3 chain engine (old proof of work): auto, avx512x2, ..., sse2
  --priority 0-5      Windows only; on Linux use nice (e.g. nice -n 19 ./mds-cpu ...)
  --affinity          pin every thread to one logical CPU
  --verify-s S        reference check every S seconds (default 60, 0 = off)
  --stats S           statistics every S seconds (default 30)
  --pool URL          stratum+ssl://host:port or stratum+tcp://host:port (repeat for failover)
  --failback S        on a fallback pool, try the first --pool again after S seconds (default 900)
  --pass P, --rig NAME, --dialect 0|2, --insecure, --pool-log, --log FILE, --verbose

Dev fee
  2% of the mining time goes to the developer: 2 minutes out of every 100 the miner logs in
  to the same pool with the developer's address (and, for merged mining, the developer's
  midwimble address), then goes back to yours. It is announced at start-up and in --help;
  the windows are logged with --pool-log.

Pools
  LuckyPool (eu.lproute.com) and the midstate reference pool software (classic stratum,
  e.g. midwimble.ariabrain.com:3357) both work. --user ADDRESS.worker: on a classic pool the
  address and the worker name are sent separately, as the pool expects.

Running together with a GPU miner on the same PC
  Use a different worker name. The CPU threads run at the lowest priority, so the GPU
  miner always gets the CPU time it needs; if its hashrate drops anyway, leave one or two
  threads free (--threads N-2).
