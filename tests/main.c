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

unsigned option_flags = bench_32 | bench_64 | bench_le
#ifdef T1HA0_AESNI_AVAILABLE
                        | bench_aes | bench_avx
#ifndef __e2k__
                        | bench_avx2
#endif /* !__e2k__ */
#endif /* T1HA0_AESNI_AVAILABLE */
                        | bench_tiny | bench_medium | bench_verbose;

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;

  bool failed = false;
  failed |= verify("t1ha2_atonce", t1ha2_atonce, refval_2atonce, true);
  failed |=
      verify("t1ha2_atonce128", thunk_t1ha2_atonce128, refval_2atonce128, true);
  failed |= verify("t1ha2_stream", thunk_t1ha2_stream, refval_2stream, true);
  failed |=
      verify("t1ha2_stream128", thunk_t1ha2_stream128, refval_2stream128, true);
  failed |= verify("t1ha1_64le", t1ha1_le, refval_64le, false);
  failed |= verify("t1ha1_64be", t1ha1_be, refval_64be, false);
  failed |= verify("t1ha0_32le", t1ha0_32le, refval_32le, false);
  failed |= verify("t1ha0_32be", t1ha0_32be, refval_32be, false);

#ifdef __e2k__
  failed |= verify("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, refval_ia32aes_a,
                   false);
  failed |=
      verify("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, refval_ia32aes_a, false);
#elif defined(T1HA0_AESNI_AVAILABLE)
  if (ia32_cpu_features.basic.ecx & UINT32_C(0x02000000)) {
    failed |= verify("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx,
                     refval_ia32aes_a, false);
    if ((ia32_cpu_features.basic.ecx & UINT32_C(0x1A000000)) ==
        UINT32_C(0x1A000000)) {
      failed |= verify("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, refval_ia32aes_a,
                       false);
      if (ia32_cpu_features.extended_7.ebx & 32)
        failed |= verify("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2,
                         refval_ia32aes_b, false);
    }
  }
#endif /* T1HA0_AESNI_AVAILABLE */

  if (failed)
    return EXIT_FAILURE;

  printf("\nPreparing to benchmarking...\n");
  fflush(NULL);
  if (!mera_init()) {
    printf(" - sorry, usable clock-source unavailable\n");
    return EXIT_SUCCESS;
  }

  if (mera.cpunum >= 0)
    printf(" - running on CPU#%d\n", mera.cpunum);
  printf(" - use %s as clock source for benchmarking\n", mera.source);
  printf(" - assume it %s and %s\n",
         (mera.flags & timestamp_clock_cheap) ? "cheap" : "costly",
         (mera.flags & timestamp_clock_stable)
             ? "stable"
             : "floating (RESULTS MAY VARY AND BE USELESS)");

  printf(" - measure granularity and overhead: ");
  fflush(NULL);
  double mats /* MeasurAble TimeSlice */ = bench_mats();
  printf("%g %s, %g iteration/%s\n", mats, mera.units, 1 / mats, mera.units);

  if (is_option_set(bench_verbose)) {
    printf(" - convergence: ");
    if (mera_bci.retry_count)
      printf("retries %u, ", mera_bci.retry_count);
    printf("restarts %u, accounted-loops %u, worthless-loops %u, spent <%us\n",
           mera_bci.restart_count, mera_bci.overhead_accounted_loops,
           mera_bci.overhead_worthless_loops, mera_bci.spent_seconds);
    printf(" - mats/overhead: best %" PRIu64 ", gate %" PRIu64
           ", inner-loops-max %u, best-count %u\n",
           mera_bci.overhead_best, mera_bci.overhead_gate,
           mera_bci.overhead_loops_max, mera_bci.overhead_best_count);
  }
  fflush(NULL);

#if defined(T1HA0_AESNI_AVAILABLE) && !defined(__e2k__)
  if ((ia32_cpu_features.basic.ecx & UINT32_C(0x02000000)) == 0)
    option_flags &= ~bench_aes;
  if ((ia32_cpu_features.basic.ecx & UINT32_C(0x1A000000)) !=
      UINT32_C(0x1A000000))
    option_flags &= ~bench_avx;
  if ((ia32_cpu_features.extended_7.ebx & 32) == 0)
    option_flags &= ~bench_avx2;
#endif /* T1HA0_AESNI_AVAILABLE */

#if !defined(__OPTIMIZE__) && (defined(_MSC_VER) && defined(_DEBUG))
  bench_size(1, "Non-optimized/Debug");
  printf("\nNon-optimized/Debug build, skip benchmark\n");
#else
  if (is_option_set(bench_tiny))
    bench_size(5, "tiny");
  if (is_option_set(bench_small))
    bench_size(31, "small");
  if (is_option_set(bench_medium))
    bench_size(1024, "medium");
  if (is_option_set(bench_large))
    bench_size(1024 * 256, "large");
#endif /* __OPTIMIZE__ */

  return EXIT_SUCCESS;
}
