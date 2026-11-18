# mds-cpu

A fast CPU miner for **Midstate (MDS)** on x86-64, for Windows and Linux.

- **Midstate Walk** (the proof of work from block 371,500) and the older BLAKE3 chain; the
  miner picks the right one from the block height of each pool job.
- Pools: **LuckyPool** (`eu.lproute.com`) and pools running the **midstate reference pool**
  software (classic stratum, e.g. `midwimble.ariabrain.com:3357`), TCP or TLS, with failover.
- **Merged mining of midwimble**: put your midwimble address in `--midwimble` (or as the pool
  password).
- Measured: **14.6 kH/s** on a Ryzen 9 7950X3D (16 cores / 32 threads) with version 0.2.1; the
  midstate documentation lists 13.0 kH/s for the official miner on a 16-core Zen 4.

## Download

Windows builds are on the [Releases](../../releases) page: unzip, run `test.bat`, put your
address in `start_mds_cpu.bat`, start it. `package/README.txt` has the full instructions and
every option.

```
mds-cpu --pool stratum+tcp://midwimble.ariabrain.com:3357 --user MSS_ADDRESS.worker --midwimble MW_ADDRESS
mds-cpu --pool stratum+ssl://eu.lproute.com:8960 --user MSS_ADDRESS.worker
mds-cpu --test        mds-cpu --bench 60        mds-cpu --tune
```

Use a reusable MSS address (`midstate wallet generate-mss`).

## How it works

One Walk attempt is a single chain of 2^18 dependent steps over a private 256 KiB scratchpad,
so on its own it leaves a core waiting on its L2 cache. mds-cpu steps several walks of
different nonces in turn on every thread (`--walk-k`, 1 to 6; measured at start-up), so the
out-of-order core overlaps them. The step is written out separately for every walk and
register, which keeps each operation dispatch predictable; AES-NI does the AES rounds, and the
scratchpads go into large pages when the system allows (`setup_large_pages.bat` on Windows).

Every engine is checked at `--test` against the known answers of midstate's `walk.rs` and
against a portable reference (`src/walk_ref.c`); while mining, one result a minute is
recomputed with the reference, so an unstable CPU shows up as `errors` in the statistics.

## Dev fee

**2% of the mining time goes to the developer.** Two minutes out of every 100 the miner logs in
to the same pool with the developer's MDS address (and the developer's midwimble address for
merged mining), then goes back to yours. It is announced at start-up and in `--help`; the
windows appear in the log with `--pool-log`. The addresses are `FEE_ADDR` and `FEE_MWB` in
`src/mds_cpu.c`. `FEE=0 sh build.sh` builds without it.

## Build

Linux, or Linux cross-compiling for Windows:

```
sudo apt install gcc git python3 mingw-w64      # mingw-w64 only for the Windows build
sh build.sh linux      # -> build/lin/mds-cpu
sh build.sh win        # -> build/win/mds-cpu.exe
```

The first run downloads and builds Mbed TLS 3.6.4. Tests:

```
build/lin/mds-cpu --test
E2E_WALK=1 python3 tests/e2e_pool.py 60       # fake LuckyPool, every share verified
python3 tests/e2e_classic.py 60               # fake midstate reference pool
```

## Layout

| Path | What |
|---|---|
| `src/mds_cpu.c` | miner: options, threads, pool client, dev fee, test / bench / tune |
| `src/walk_engine.c`, `walk_engine_body.h`, `walk_b3.h` | Midstate Walk engines (soft, AES-NI, AVX2 build) |
| `src/walk_ref.c` | portable Walk reference |
| `src/mds_cpu_engine.c`, `tools/gen_cpu_core.py` | BLAKE3 chain engines (SSE2, AVX2, AVX-512) |
| `package/` | the scripts and README of the Windows package |
| `tests/` | end-to-end tests against fake pools |

## License

GPL v3 or later, see [LICENSE](LICENSE). Third-party parts are listed in
[THIRD-PARTY.md](THIRD-PARTY.md). No warranty: mining stresses hardware, use it at your own risk.
