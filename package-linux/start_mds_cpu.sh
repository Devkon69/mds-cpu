#!/bin/sh
# start_mds_cpu.sh - mines Midstate (MDS) with the CPU (Midstate Walk).
# Put your reusable MSS address here (midstate wallet generate-mss) and a worker name.
USER_ADDR=YOUR_MSS_ADDRESS
RIG=cpu
# Pool password: x if not needed; on a midstate pool a midwimble address here = merged mining
PASS=x
POOL=stratum+ssl://eu.lproute.com:8960
# Extra options, e.g. the line printed by ./mds-cpu --tune (--threads N --walk-k K --walk-engine E)
EXTRA=

cd "$(dirname "$0")"
if [ "$USER_ADDR" = "YOUR_MSS_ADDRESS" ]; then echo "Edit start_mds_cpu.sh and put your MSS address in USER_ADDR."; exit 2; fi
while :; do
    ./mds-cpu --pool "$POOL" --user "$USER_ADDR.$RIG" --pass "$PASS" --log mds-cpu.log $EXTRA
    echo "mds-cpu stopped (code $?): restarting in 10 s, Ctrl-C to quit."
    sleep 10 || exit 0
done
