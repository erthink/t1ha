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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#if defined(_MSC_VER)
#pragma warning(disable : 4127) /* conditional expression is constant */
#if _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif
#endif /* MSVC */

#include "../t1ha.h" /* for byteorder and common __ia32__ */

/*****************************************************************************/

typedef uint64_t timestamp_t;

enum mera_flags {
  timestamp_clock_have = 1u << 0,
  timestamp_clock_cheap = 1u << 1,
  timestamp_ticks = 1u << 2,
  timestamp_cycles = 1u << 3,
  timestamp_clock_stable = 1u << 4,
};

typedef struct {
  unsigned (*start)(timestamp_t *);
  unsigned (*finish)(timestamp_t *);
  double (*convert)(timestamp_t);
  const char *units;
  const char *source;
  unsigned flags;
  int cpunum;
} mera_t;

extern mera_t mera;
bool mera_init(void);

typedef struct {
  unsigned retry_count, restart_count;
  unsigned overhead_loops_max, overhead_best_count, overhead_accounted_loops,
      overhead_worthless_loops;
  uint64_t overhead_best, overhead_gate;

  unsigned target_loops, tail_loops_max, target_best_count,
      target_accounted_loops, target_worthless_loops, spent_seconds;
  uint64_t target_best, target_gate;
} mera_bci_t /* bci = Bench Convergence Info */;

extern mera_bci_t mera_bci;
typedef uint64_t (*mera_bench_target_t)(const void *data, size_t bytes,
                                        uint64_t seed);

#define MERA_BENCH_TARGET mera_bench_target_t
#define MERA_BENCH_SELF_ARGS const void *data, size_t bytes, uint64_t seed
#define MERA_BENCH_TARGET_ARGS data, bytes, seed
#define MERA_PERROR_PREFIX " - "

double mera_bench(MERA_BENCH_TARGET target, MERA_BENCH_SELF_ARGS);

/*****************************************************************************/

#if defined(__ia32__)
typedef struct _ia32_cpu_features {
  struct {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
  } basic /* https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits
           */
      ,
      extended_7 /* https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=0:_Extended_Features
                  */
      ;

  struct {
    uint32_t ecx;
    uint32_t edx;
  } extended_80000001 /* https://en.wikipedia.org/wiki/CPUID#EAX=80000001h:_Extended_Processor_Info_and_Feature_Bits
                       */
      ;

  struct {
    uint32_t ecx;
    uint32_t edx;
  } extended_80000007 /*  Advanced Power Management Information */;

} ia32_cpu_features_t;

extern ia32_cpu_features_t ia32_cpu_features;
void ia32_fetch_cpu_features(void);
#endif /* __ia32__ */
