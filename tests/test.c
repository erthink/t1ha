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

#include "../src/t1ha_selfcheck.h"
#include "common.h"

#include <stdio.h>

#if defined(_MSC_VER)
#if _MSC_VER < 1900
#define snprintf _snprintf
#pragma warning(disable : 4996) /* '_snprintf': This function or variable      \
                                   may be unsafe */
#endif
#endif /* MSVC */

/*****************************************************************************/

#ifndef T1HA2_DISABLED
uint64_t thunk_t1ha2_atonce128(const void *data, size_t len, uint64_t seed) {
  uint64_t unused;
  return t1ha2_atonce128(&unused, data, len, seed);
}

uint64_t thunk_t1ha2_stream(const void *data, size_t len, uint64_t seed) {
  t1ha_context_t ctx;
  t1ha2_init(&ctx, seed, seed);
  t1ha2_update(&ctx, data, len);
  return t1ha2_final(&ctx, NULL);
}

uint64_t thunk_t1ha2_stream128(const void *data, size_t len, uint64_t seed) {
  t1ha_context_t ctx;
  t1ha2_init(&ctx, seed, seed);
  t1ha2_update(&ctx, data, len);
  uint64_t unused;
  return t1ha2_final(&ctx, &unused);
}
#endif /* T1HA2_DISABLED */

static bool probe(uint64_t (*hash)(const void *, size_t, uint64_t),
                  const char *caption, const uint64_t check, const void *data,
                  unsigned len, uint64_t seed) {
  uint64_t value = hash(data, len, seed);
  if (is_option_set(test_verbose) || (value != check))
    printf("Pattern '%s', reference value %08X%08X: ", caption,
           (uint32_t)(check >> 32), (uint32_t)check);
  if (check == value) {
    if (is_option_set(test_verbose))
      printf("Passed\n");
    return false;
  }
  if (!is_option_set(test_quiet))
    printf("Failed! Got %08X%08X\n", (uint32_t)(value >> 32), (uint32_t)value);
  return true;
}

bool verify(const char *title, uint64_t (*hash)(const void *, size_t, uint64_t),
            const uint64_t *reference_values) {
  if (!is_option_set(test_quiet))
    printf("Testing %s...%s", title, is_option_set(test_verbose) ? "\n" : "");

  const uint64_t zero = 0;
  bool failed = false;
  failed |= probe(hash, "empty-zero", *reference_values++, NULL, 0, zero);
  failed |= probe(hash, "empty-all1", *reference_values++, NULL, 0, ~zero);
  failed |= probe(hash, "bin64-zero", *reference_values++, t1ha_test_pattern,
                  64, zero);

  char caption[32];
  uint64_t seed = 1;
  for (int i = 1; i < 64; i++) {
    snprintf(caption, sizeof(caption), "bin%02i-1p%02u", i, i & 63);
    failed |=
        probe(hash, caption, *reference_values++, t1ha_test_pattern, i, seed);
    seed <<= 1;
  }

  seed = ~zero;
  for (int i = 1; i <= 7; i++) {
    seed <<= 1;
    snprintf(caption, sizeof(caption), "align%i_F%u", i, 64 - i);
    failed |= probe(hash, caption, *reference_values++, t1ha_test_pattern + i,
                    64 - i, seed);
  }

  uint8_t pattern_long[512];
  for (size_t i = 0; i < sizeof(pattern_long); ++i)
    pattern_long[i] = (uint8_t)i;
  for (int i = 0; i <= 7; i++) {
    snprintf(caption, sizeof(caption), "long-%05u", 128 + i * 17);
    failed |= probe(hash, caption, *reference_values++, pattern_long + i,
                    128 + i * 17, seed);
  }

  if (!is_option_set(test_quiet))
    printf(" %s\n", (!is_option_set(test_verbose) && !failed) ? "Ok" : "");
  return failed;
}
