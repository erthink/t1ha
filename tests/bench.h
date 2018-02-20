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

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#pragma warning(disable : 4711) /* function 'xyz' selected for                 \
                                   automatic inline expansion */
#pragma warning(disable : 4127) /* conditional expression is constant */
#if _MSC_VER < 1900
#define snprintf _snprintf
#pragma warning(disable : 4996) /* '_snprintf': This function or variable      \
                                   may be unsafe */
#endif
#if _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif
#endif /* MSVC */

#include "../t1ha.h"

/*****************************************************************************/

typedef uint64_t timestamp_t;

enum mera_flags {
  timestamp_clock_cheap = 1u << 0,
  timestamp_clock_stable = 1u << 1,
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
void mera_init(void);

/*****************************************************************************/

#if T1HA_IA32_AVAILABLE
typedef struct _ia32_cpu_features {
  struct {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
  } basic /* https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits */,
      extended_7 /* https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=0:_Extended_Features */;

  struct {
    uint32_t ecx;
    uint32_t edx;
  } extended_80000001 /* https://en.wikipedia.org/wiki/CPUID#EAX=80000001h:_Extended_Processor_Info_and_Feature_Bits */;

  struct {
    uint32_t ecx;
    uint32_t edx;
  } extended_80000007 /*  Advanced Power Management Information */;

} ia32_cpu_features_t;

extern ia32_cpu_features_t ia32_cpu_features;
#endif /* T1HA_IA32_AVAILABLE */

/*****************************************************************************/

double bench_mats(void);
void bench(const char *caption,
           uint64_t (*hash)(const void *, size_t, uint64_t), const void *data,
           unsigned len, uint64_t seed);
