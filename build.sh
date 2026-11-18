#!/bin/sh
# build.sh - mds-cpu (Midstate Walk + BLAKE3 chain) for Windows x64 (mingw-w64) and Linux.
#   sh build.sh            both
#   sh build.sh win        only Windows
#   sh build.sh linux      only Linux
#   FEE=N sh build.sh      dev fee of N % (default 2, FEE=0 for none)
# Needs: gcc, python3, git; for Windows x86_64-w64-mingw32-gcc-posix (mingw-w64).
# The first run fetches and builds Mbed TLS 3.6.4 (TLS to the pool) into ext/ and build/.
set -e
cd "$(dirname "$0")"
MBED=ext/mbedtls/include
FEE="${FEE:-2}"
what="${1:-all}"
python3 tools/gen_cpu_core.py src/mds_cpu_core.h

mbed() {    # $1 = cc, $2 = ar, $3 = out dir
    [ -f $3/libmbedall.a ] && return 0
    if [ ! -d ext/mbedtls/library ]; then
        mkdir -p ext
        git clone -q --depth 1 -b v3.6.4 https://github.com/Mbed-TLS/mbedtls.git ext/mbedtls
        (cd ext/mbedtls && git submodule update --init --depth 1 -q)
    fi
    mkdir -p $3
    for f in ext/mbedtls/library/*.c; do $1 -O2 -Iext/mbedtls/include -c $f -o $3/$(basename $f .c).o; done
    $2 rcs $3/libmbedall.a $3/*.o
}

build() {   # $1 = cc, $2 = out dir, $3 = mbedtls lib, $4 = exe name, $5.. = link flags
    cc=$1; out=$2; lib=$3; exe=$4; shift 4
    mkdir -p $out
    EF="-O3 -std=gnu11 -Isrc -fno-strict-aliasing -fno-asynchronous-unwind-tables"
    # mingw-gcc does not realign the stack past 16 bytes on Win64: never emit aligned vector moves
    case $cc in *mingw*) EF="$EF -Wa,-muse-unaligned-vector-move";; esac
    $cc $EF -DENG_SSE2 -c src/mds_cpu_engine.c -o $out/e_sse2.o
    $cc $EF -mavx2 -DENG_AVX2 -c src/mds_cpu_engine.c -o $out/e_avx2.o
    $cc $EF -mavx512f -mavx512vl -DENG_AVX512VL -c src/mds_cpu_engine.c -o $out/e_avx512vl.o
    $cc $EF -mavx512f -DENG_AVX512 -c src/mds_cpu_engine.c -o $out/e_avx512.o
    # Midstate Walk engines
    $cc $EF -DWE_SOFT -DWE_AHEAD -c src/walk_engine.c -o $out/w_soft.o
    $cc $EF -DWE_AESNI -DWE_AHEAD -maes -msse4.1 -c src/walk_engine.c -o $out/w_aesni.o
    $cc $EF -DWE_V3 -DWE_AHEAD -DWE_ADDR -march=x86-64-v3 -maes -c src/walk_engine.c -o $out/w_v3.o
    $cc -O2 -std=gnu11 -Wall -Wno-unused-function -D_WIN32_WINNT=0x0601 -DFEE_PCT=$FEE ${FEE_CYCLE:+-DFEE_CYCLE=$FEE_CYCLE} -I$MBED -Isrc \
        -o $out/$exe src/mds_cpu.c src/cJSON.c src/walk_ref.c $out/e_*.o $out/w_*.o $lib "$@"
    ls -la $out/$exe
}

case $what in
    win|all) mbed x86_64-w64-mingw32-gcc-posix x86_64-w64-mingw32-ar build/mbedtls-win
             build x86_64-w64-mingw32-gcc-posix build/win build/mbedtls-win/libmbedall.a mds-cpu.exe -lws2_32 -lbcrypt -ladvapi32 -lpthread -static -s;;
esac
case $what in
    linux|all) mbed gcc ar build/mbedtls-lin
               build gcc build/lin build/mbedtls-lin/libmbedall.a mds-cpu -lpthread -lm;;
esac
