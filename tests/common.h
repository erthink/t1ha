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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#pragma warning(disable : 4127) /* conditional expression is constant */
#if _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif
#endif /* MSVC */

#include "../t1ha.h" /* for T1HA0_AESNI_AVAILABLE, __ia32__, etc */
#include "mera.h"    /* for ia32_cpu_features */

enum test_flags {
  test_verbose = 1 << 0,
  bench_verbose = 1 << 1,

  bench_32 = 1 << 2,
  bench_64 = 1 << 3,
  bench_le = 1 << 4,
  bench_be = 1 << 5,
#ifdef T1HA0_AESNI_AVAILABLE
  bench_aes = 1 << 6,
  bench_avx = 1 << 7,
#ifndef __e2k__
  bench_avx2 = 1 << 8,
#endif /* !__e2k__ */
#endif /* T1HA0_AESNI_AVAILABLE */

  bench_tiny = 1 << 9,
  bench_small = 1 << 10,
  bench_medium = 1 << 11,
  bench_large = 1 << 12,
};

extern unsigned option_flags;

static __inline bool is_option_set(unsigned mask) {
  return (option_flags & mask) == mask;
}

extern const uint64_t refval_2atonce[80];
extern const uint64_t refval_2atonce128[80];
extern const uint64_t refval_2stream[80];
extern const uint64_t refval_2stream128[80];
extern const uint64_t refval_64le[80];
extern const uint64_t refval_64be[80];
extern const uint64_t refval_32le[80];
extern const uint64_t refval_32be[80];

#ifdef T1HA0_AESNI_AVAILABLE
uint64_t t1ha0_ia32aes_noavx_a(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx_a(const void *data, size_t length, uint64_t seed);
#ifndef __e2k__
uint64_t t1ha0_ia32aes_avx2_a(const void *data, size_t length, uint64_t seed);
#endif /* !__e2k__ */
extern const uint64_t refval_ia32aes_a[80];

uint64_t t1ha0_ia32aes_noavx_b(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx_b(const void *data, size_t length, uint64_t seed);
#ifndef __e2k__
uint64_t t1ha0_ia32aes_avx2_b(const void *data, size_t length, uint64_t seed);
#endif /* !__e2k__ */
extern const uint64_t refval_ia32aes_b[80];
#endif /* T1HA0_AESNI_AVAILABLE */

bool verify(const char *title, uint64_t (*hash)(const void *, size_t, uint64_t),
            const uint64_t *reference_values, bool ignore_errors);

uint64_t thunk_t1ha2_atonce128(const void *data, size_t len, uint64_t seed);
uint64_t thunk_t1ha2_stream(const void *data, size_t len, uint64_t seed);
uint64_t thunk_t1ha2_stream128(const void *data, size_t len, uint64_t seed);

double bench_mats(void);
void bench(const char *caption,
           uint64_t (*hash)(const void *, size_t, uint64_t), const void *data,
           unsigned len, uint64_t seed);

void bench_size(const unsigned size, const char *caption);
