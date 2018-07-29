/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#include "common.h"
#include <stdio.h>
#include <stdlib.h>

double bench_mats(void) { return mera_bench(NULL, NULL, 0, 0); }

void bench(const char *caption,
           uint64_t (*hash)(const void *, size_t, uint64_t), const void *data,
           unsigned len, uint64_t seed) {

  printf("%-24s: ", caption);
  fflush(NULL);

  double value = mera_bench(hash, data, len, seed);
  printf("%10.3f %s/hash, %6.3f %s/byte, %6.3f byte/%s", value, mera.units,
         value / len, mera.units, len / value, mera.units);

  if (mera.flags & timestamp_cycles) {
    printf(", %6.3f Gb/s @3GHz", 3.0 * len / value);
  } else if ((mera.flags & timestamp_ticks) == 0) {
    printf(", %6.3f Gb/s", len / value);
  }
  printf(" %s\n", (mera.flags & timestamp_clock_stable) ? "" : "roughly");

  if (is_option_set(bench_verbose)) {
    printf(" - convergence: ");
    if (mera_bci.retry_count)
      printf("retries %u, ", mera_bci.retry_count);
    printf("restarts %u, accounted-loops %u, worthless-loops %u, spent <%us\n",
           mera_bci.restart_count, mera_bci.target_accounted_loops,
           mera_bci.target_worthless_loops, mera_bci.spent_seconds);
    printf(" - mats/overhead: best %" PRIu64 ", gate %" PRIu64
           ", inner-loops-max %u, best-count %u\n",
           mera_bci.overhead_best, mera_bci.overhead_gate,
           mera_bci.overhead_loops_max, mera_bci.overhead_best_count);
    printf(" - hash: loops %u, best %" PRIu64 ", gate %" PRIu64
           ", tailloops-max %u, best-count %u\n\n",
           mera_bci.target_loops, mera_bci.target_best, mera_bci.target_gate,
           mera_bci.tail_loops_max, mera_bci.target_best_count);
  }
  fflush(NULL);
}

uint64_t thunk_XXH32(const void *input, size_t length, uint64_t seed) {
  return XXH32(input, length, (uint32_t)seed);
}

uint64_t thunk_HighwayHash64_pure_c(const void *input, size_t length,
                                    uint64_t seed) {
  uint64_t key[4] = {seed, seed, seed, seed};
  return HighwayHash64_pure_c(key, input, length);
}

void bench_size(const unsigned size, const char *caption) {
  printf("\nBench for %s keys (%u bytes):\n", caption, size);
  const uint64_t seed = ~UINT64_C(42);
  char *buffer = malloc(size);
  for (unsigned i = 0; i < size; ++i)
    buffer[i] = (char)(rand() + i);

#ifndef T1HA2_DISABLED
  if (is_selected(bench_64 | bench_2)) {
    bench("t1ha2_atonce", t1ha2_atonce, buffer, size, seed);
    bench("t1ha2_atonce128*", thunk_t1ha2_atonce128, buffer, size, seed);
    bench("t1ha2_stream*", thunk_t1ha2_stream, buffer, size, seed);
    bench("t1ha2_stream128*", thunk_t1ha2_stream128, buffer, size, seed);
  }
#endif

#ifndef T1HA1_DISABLED
  if (is_selected(bench_64 | bench_le | bench_1))
    bench("t1ha1_64le", t1ha1_le, buffer, size, seed);
  if (is_selected(bench_64 | bench_be | bench_1))
    bench("t1ha1_64be", t1ha1_be, buffer, size, seed);
#endif

#ifndef T1HA0_DISABLED
  if (is_selected(bench_0))
    bench("t1ha0", t1ha0, buffer, size, seed);
  if (is_selected(bench_32 | bench_le | bench_0))
    bench("t1ha0_32le", t1ha0_32le, buffer, size, seed);
  if (is_selected(bench_32 | bench_be | bench_0))
    bench("t1ha0_32be", t1ha0_32be, buffer, size, seed);

#if T1HA0_AESNI_AVAILABLE
  if (is_selected(bench_aes)) {
    bench("t1ha0_ia32aes_noavx_a", t1ha0_ia32aes_noavx_a, buffer, size, seed);
    bench("t1ha0_ia32aes_noavx_b", t1ha0_ia32aes_noavx_b, buffer, size, seed);
    bench("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, buffer, size, seed);
    if (is_selected(bench_avx)) {
      bench("t1ha0_ia32aes_avx_a", t1ha0_ia32aes_avx_a, buffer, size, seed);
      bench("t1ha0_ia32aes_avx_b", t1ha0_ia32aes_avx_b, buffer, size, seed);
      bench("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, buffer, size, seed);
    }
#ifndef __e2k__
    if (is_selected(bench_avx2)) {
      bench("t1ha0_ia32aes_avx2_a", t1ha0_ia32aes_avx2_a, buffer, size, seed);
      bench("t1ha0_ia32aes_avx2_b", t1ha0_ia32aes_avx2_b, buffer, size, seed);
      bench("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2, buffer, size, seed);
    }
#endif /* !__e2k__ */
  }
#endif /* T1HA0_AESNI_AVAILABLE */
#endif /* T1HA0_DISABLED */

  if (is_selected(bench_xxhash)) {
    bench("xxhash32", thunk_XXH32, buffer, size, (uint32_t)seed);
    bench("xxhash64", XXH64, buffer, size, seed);
  }
  if (is_selected(bench_stadtx)) {
    bench("StadtX", thunk_StadtX, buffer, size, seed);
  }
  if (is_selected(bench_highwayhash)) {
    bench("HighwayHash64_pure_c", thunk_HighwayHash64_pure_c, buffer, size,
          seed);
    bench("HighwayHash64_portable", thunk_HighwayHash64_Portable, buffer, size,
          seed);
#ifdef __ia32__
    if (ia32_cpu_features.basic.ecx & (1ul << 19))
      bench("HighwayHash64_sse41", thunk_HighwayHash64_SSE41, buffer, size,
            seed);
    if (ia32_cpu_features.extended_7.ebx & 32)
      bench("HighwayHash64_avx2", thunk_HighwayHash64_AVX2, buffer, size, seed);
#endif
#ifdef __e2k__
    bench("HighwayHash64_sse41", thunk_HighwayHash64_SSE41, buffer, size, seed);
#endif
    /* TODO: thunk_HighwayHash64_VSX() */
  }
  free(buffer);
}
