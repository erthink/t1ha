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
#pragma warning(disable : 4204) /* nonstandard extension used: non-constant    \
                                   aggregate initializer */
#endif                          /* MSVC */

#include "../src/t1ha_selfcheck.h"
#include "../t1ha.h" /* for T1HA0_AESNI_AVAILABLE, __ia32__, etc */
#include "mera.h"    /* for ia32_cpu_features */

enum test_flags {
  test_verbose = 1u << 0,
  test_quiet = 1u << 1,
  hash_stdin_strings = 1u << 2,
  bench_verbose = 1u << 3,
  bench_xxhash = 1u << 4,
  bench_highwayhash = 1u << 5,
  bench_stadtx = 1u << 6,
  /* 7 */

  bench_0 = 1u << 8,
  bench_1 = 1u << 9,
  bench_2 = 1u << 10,
  bench_3 = 1u << 11,
  bench_4 = 1u << 12,
  bench_5 = 1u << 13,
  bench_6 = 1u << 14,
  bench_7 = 1u << 15,

  bench_tiny = 1u << 16,
  bench_small = 1u << 17,
  bench_medium = 1u << 18,
  bench_large = 1u << 19,
  bench_huge = 1u << 20,
  /* 21, 22, 23 */
  bench_size_flags =
      bench_tiny | bench_small | bench_medium | bench_large | bench_huge,

  bench_32 = 1u << 24,
  bench_64 = 1u << 25,
  bench_le = 1u << 26,
  bench_be = 1u << 27,
#if T1HA0_AESNI_AVAILABLE || defined(__ia32__)
  bench_aes = 1u << 28,
  bench_avx = 1u << 29,
#ifndef __e2k__
  bench_avx2 = 1u << 30,
#endif /* !__e2k__ */
  user_wanna_aes = 1u << 31,
#endif /* T1HA0_AESNI_AVAILABLE */

  bench_funcs_flags = bench_0 | bench_1 | bench_2 | bench_3 | bench_4 |
                      bench_5 | bench_6 | bench_7 | bench_32 | bench_64 |
                      bench_le | bench_be | 1u << 28 | 1u << 29 | 1u << 30 |
                      1u << 31 | bench_xxhash | bench_highwayhash | bench_stadtx
};

extern unsigned option_flags, disabled_option_flags;

static __inline bool is_option_set(unsigned mask) {
  return (option_flags & mask) != 0;
}

static __inline bool is_selected(unsigned mask) {
  return is_option_set(mask) && (disabled_option_flags & mask) == 0;
}

#if T1HA0_AESNI_AVAILABLE
uint64_t t1ha0_ia32aes_noavx_a(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx_a(const void *data, size_t length, uint64_t seed);
#ifndef __e2k__
uint64_t t1ha0_ia32aes_avx2_a(const void *data, size_t length, uint64_t seed);
#endif /* !__e2k__ */

uint64_t t1ha0_ia32aes_noavx_b(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx_b(const void *data, size_t length, uint64_t seed);
#ifndef __e2k__
uint64_t t1ha0_ia32aes_avx2_b(const void *data, size_t length, uint64_t seed);
#endif /* !__e2k__ */
#endif /* T1HA0_AESNI_AVAILABLE */

bool verify(const char *title, uint64_t (*hash)(const void *, size_t, uint64_t),
            const uint64_t *reference_values);

uint64_t thunk_t1ha2_atonce128(const void *data, size_t len, uint64_t seed);
uint64_t thunk_t1ha2_stream(const void *data, size_t len, uint64_t seed);
uint64_t thunk_t1ha2_stream128(const void *data, size_t len, uint64_t seed);

double bench_mats(void);
void bench(const char *caption,
           uint64_t (*hash)(const void *, size_t, uint64_t), const void *data,
           unsigned len, uint64_t seed);

void bench_size(const unsigned size, const char *caption);

/*****************************************************************************/
/* Other hashes, just for comparison */

/* xxHash */
uint64_t XXH64(const void *input, size_t length, uint64_t seed);
uint32_t XXH32(const void *input, size_t length, uint32_t seed);
uint64_t thunk_XXH32(const void *input, size_t length, uint64_t seed);

/* StadtX hash */
uint64_t thunk_StadtX(const void *input, size_t length, uint64_t seed);
extern const uint64_t refval_StadtX[];

/* HighwayHash */
typedef uint64_t (*HighwayHash64_t)(const uint64_t key[4], const uint8_t *data,
                                    size_t size);

bool HighwayHash64_verify(HighwayHash64_t fn, const char *title);

/* HighwayHash C */
#include "highwayhash/pure_c.h"
uint64_t thunk_HighwayHash64_pure_c(const void *input, size_t length,
                                    uint64_t seed);

/* HighwayHash CXX */
uint64_t HighwayHash64_Portable(const uint64_t key[4], const uint8_t *data,
                                size_t size);
uint64_t HighwayHash64_AVX2(const uint64_t key[4], const uint8_t *data,
                            size_t size);
uint64_t HighwayHash64_SSE41(const uint64_t key[4], const uint8_t *data,
                             size_t size);
uint64_t HighwayHash64_VSX(const uint64_t key[4], const uint8_t *data,
                           size_t size);

uint64_t thunk_HighwayHash64_Portable(const void *input, size_t length,
                                      uint64_t seed);
uint64_t thunk_HighwayHash64_AVX2(const void *input, size_t length,
                                  uint64_t seed);
uint64_t thunk_HighwayHash64_SSE41(const void *input, size_t length,
                                   uint64_t seed);
uint64_t thunk_HighwayHash64_VSX(const void *input, size_t length,
                                 uint64_t seed);
