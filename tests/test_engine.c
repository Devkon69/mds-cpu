/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mds_pow.h"
typedef int (*eng_fn)(const uint32_t*, uint32_t, uint32_t, uint32_t, uint32_t*, volatile const uint32_t*, uint32_t);
#define D(n) int n(const uint32_t*, uint32_t, uint32_t, uint32_t, uint32_t*, volatile const uint32_t*, uint32_t);
D(mds_chain_sse2_g1) D(mds_chain_sse2_g2) D(mds_chain_avx2_g1) D(mds_chain_avx2_g2)
D(mds_chain_avx512vl_g1) D(mds_chain_avx512vl_g2) D(mds_chain_avx512_g1) D(mds_chain_avx512_g2)
static struct { const char *n; eng_fn f; int lanes; } E[] = {
 {"sse2 g1",mds_chain_sse2_g1,4},{"sse2 g2",mds_chain_sse2_g2,8},{"avx2 g1",mds_chain_avx2_g1,8},{"avx2 g2",mds_chain_avx2_g2,16},
 {"avx512vl g1",mds_chain_avx512vl_g1,8},{"avx512vl g2",mds_chain_avx512vl_g2,16},{"avx512 g1",mds_chain_avx512_g1,16},{"avx512 g2",mds_chain_avx512_g2,32}};
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
int main(int argc,char**argv){
  int iters = argc>1?atoi(argv[1]):100; int bench = argc>2?atoi(argv[2]):0;
  uint8_t mid[32]; for(int i=0;i<32;i++) mid[i]=rand();
  uint32_t m[8]; for(int i=0;i<8;i++) m[i]=mid[4*i]|mid[4*i+1]<<8|mid[4*i+2]<<16|(uint32_t)mid[4*i+3]<<24;
  uint32_t hi=0x9abcdef1, lo=0xfffffff0; int fails=0;
  for(unsigned e=0;e<8;e++){
    uint32_t out[32*8];
    double t0=now(); E[e].f(m,hi,lo,iters,out,NULL,0); double dt=now()-t0;
    int bad=0;
    if(!bench) for(int l=0;l<E[e].lanes;l++){ uint8_t ref[32]; mds_extension(mid,(uint64_t)hi<<32|(uint32_t)(lo+l),iters,ref); if(memcmp(ref,out+l*8,32)) bad++; }
    fails+=bad;
    printf("%-12s lanes %2d: %s  %.1f M compressions/s/thread = %.1f H/s/thread\n",E[e].n,E[e].lanes,bad?"FAIL":"OK",E[e].lanes*(double)iters/dt/1e6,E[e].lanes/dt*iters/1000001.0);
  }
  printf(fails?"FAILURES\n":"ALL OK\n"); return fails!=0;
}
