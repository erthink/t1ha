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
#include <string.h>

const unsigned default_option_flags = bench_0 | bench_1 | bench_2 |
                                      bench_xxhash | bench_highwayhash |
                                      bench_stadtx | bench_tiny | bench_large;

const unsigned available_eas_flags =
#if T1HA0_AESNI_AVAILABLE
    bench_aes | bench_avx | user_wanna_aes |
#ifndef __e2k__
    bench_avx2 |
#endif /* !__e2k__ */
#endif /* T1HA0_AESNI_AVAILABLE */
    0u;

const unsigned default_disabled_option_flags =
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    bench_le
#else
    bench_be
#endif /* BIG_ENDIAN */
    | ((UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul) ? bench_32 : 0);

unsigned option_flags, disabled_option_flags;

void usage(void) {
  printf(
      "By default                  - run reasonable tests and benchmarks\n"
      "                              for current platform\n"
      "Generic options:\n"
      "  --test-quiet              - quiet perform tests and exit with status\n"
      "  --hash-stdin-strings      - output hash for each line from stdin\n"
      "  --test-only, --no-bench   - perform tests, but don't benchmarking\n"
      "  --test-verbose            - be verbose while testing\n"
      "  --bench-verbose           - be verbose while benchmarking\n"
      "  --verbose                 - turn both --test-verbose\n"
      "                              and --bench-verbose\n"
      "Keys size choices:\n"
      "  --tiny, --no-tiny         - include/exclude 5 bytes, i.e tiny keys\n"
      "  --small, --no-small       - include/exclude 31 bytes, i.e small keys\n"
      "  --medium, --no-medium     - include/exclude 1K, i.e medium keys\n"
      "  --large, --no-large       - include/exclude 16K, i.e large keys\n"
      "  --huge, --no-huge         - include/exclude 256K, i.e huge keys\n"
      "  --all-sizes               - run benchmark for all sizes of keys\n"
      "\n"
      "Functions choices:\n"
      "  --all-funcs               - run benchmark for all functions\n"
#ifndef T1HA0_DISABLED
      "  --0, --no-0               - include/exclude t1ha0\n"
#endif
#ifndef T1HA1_DISABLED
      "  --1, --no-1               - include/exclude t1ha1\n"
#endif
#ifndef T1HA2_DISABLED
      "  --2, --no-2               - include/exclude t1ha2\n"
#endif
      "  --32, --no-32             - include/exclude 32-bit targets,\n"
      "                              i.e t1ha0_32le(), t1ha0_32be()...\n"
      "  --64, --no-64             - include/exclude 64-bit targets,\n"
      "                              i.e. t1ha1_64le(), t1ha1_64be()...\n"
      "  --le, --no-le             - include/exclude little-endian targets,\n"
      "                              i.e. t1ha0_32le(), t1ha2...\n"
      "  --be, --no-le             - include/exclude big-endian targets,\n"
      "                              i.e. t1ha0_32be(), t1ha1_64be()...\n"
#if T1HA0_AESNI_AVAILABLE
      "  --aes, --no-aes           - include/exclude AES-NI accelerated,\n"
      "                              i.e. t1ha0_ia32aes_avx(), etc...\n"
#endif /* T1HA0_AESNI_AVAILABLE */
      "\n"
      "Just for comparison:\n"
      "  --xxhash, --no-xxhash     - include/exclude xxHash32 and xxHash64\n"
      "  --stadtx, --no-stadtx     - include/exclude StadtX\n"
      "  --highway, --no-highway   - include/exclude Google's HighwayHash.\n");
}

static bool option(const char *arg, const char *opt, unsigned flag) {
  if (strncmp(arg, "--", 2) == 0 && strcmp(arg + 2, opt) == 0) {
    option_flags |= flag;
    return true;
  }
  if (strncmp(arg, "--no-", 5) == 0 && strcmp(arg + 5, opt) == 0) {
    disabled_option_flags |= flag;
    return true;
  }
  return false;
}

static void print_build_info(void) {
  printf("Build by "
#if defined(EMSCRIPTEN)
         "Emscripten/LLVM compiler"
#elseif defined(__INTEL_COMPILER)
         "Intel C/C++ compiler"
#elif defined(_MSC_VER)
         "Microsoft Visual C/C++ %lu compiler for %s",
         (unsigned long)_MSC_FULL_VER,
#if defined(_M_X64) || defined(_M_ARM64)
         "x86-64"
#elif defined(_M_IX86)
         "x86-32"
#elif defined(_M_ARM64)
         "Arm8-64"
#elif defined(_M_ARM)
         "Arm7-32"
#elif defined(_M_IA64)
         "Itanium"
#else
#error FIXME
#endif
#elif defined(__e2k__)
         "Elbrus C/C++ compiler"
#elif defined(__SUNPRO_C) || defined(__sun) || defined(sun)
         "SUN C/C++ compiler"
#elif defined(__IBMC__)
         "IBM C/C++ compiler"
#elif defined(__clang__)
         "Clang compiler %d.%d",
         __clang_major__, __clang_minor__
#elif defined(__GNUC__)
         "GNU C/C++ compiler %d.%d",
         __GNUC__, __GNUC_MINOR__
#else
         "'Unknown' compiler"
#endif
  );
  fflush(NULL);
}

int main(int argc, const char *argv[]) {
  if (argc > 1) {
    for (int i = 1; i < argc; ++i) {
      if (strcmp("--test-quiet", argv[i]) == 0) {
        option_flags = test_quiet;
        continue;
      }
      if (strcmp("--hash-stdin-strings", argv[i]) == 0) {
        option_flags = (option_flags & bench_funcs_flags) | test_quiet |
                       hash_stdin_strings;
        continue;
      }
      if (strcmp("--test-only", argv[i]) == 0 ||
          strcmp("--no-bench", argv[i]) == 0) {
        option_flags &= test_verbose;
        continue;
      }
      if (strcmp("--test-verbose", argv[i]) == 0) {
        option_flags |= test_verbose;
        continue;
      }
      if (strcmp("--bench-verbose", argv[i]) == 0) {
        option_flags |= bench_verbose;
        continue;
      }
      if (strcmp("--verbose", argv[i]) == 0 || strcmp("-v", argv[i]) == 0) {
        option_flags |= bench_verbose | test_verbose;
        continue;
      }
      if (strcmp("--bench-all", argv[i]) == 0) {
        option_flags |= ~(test_verbose | bench_verbose);
        disabled_option_flags = 0;
        continue;
      }
      if (strcmp("--all-funcs", argv[i]) == 0) {
        option_flags |= bench_funcs_flags;
        disabled_option_flags &= ~bench_funcs_flags;
        continue;
      }
      if (strcmp("--all-sizes", argv[i]) == 0) {
        option_flags |= bench_size_flags;
        disabled_option_flags &= ~bench_size_flags;
        continue;
      }
      if (strcmp("--aes", argv[i]) == 0) {
        if (available_eas_flags) {
          option_flags |= available_eas_flags;
          continue;
        }
        fprintf(stderr, "%s: AES-NI not available for '%s', bailout\n", argv[0],
                argv[i]);
        return EXIT_FAILURE;
      }
      if (strcmp("--no-aes", argv[i]) == 0) {
        if (available_eas_flags) {
          disabled_option_flags |= available_eas_flags;
        } else {
          fprintf(stderr, "%s: AES-NI not available for '%s', ignore\n",
                  argv[0], argv[i]);
        }
        continue;
      }

      if (option(argv[i], "xxhash", bench_xxhash))
        continue;

      if (option(argv[i], "highwayhash", bench_highwayhash) ||
          option(argv[i], "highway", bench_highwayhash))
        continue;

      if (option(argv[i], "stadtx", bench_stadtx))
        continue;

#ifndef T1HA0_DISABLED
      if (option(argv[i], "0", bench_0))
        continue;
#endif
#ifndef T1HA1_DISABLED
      if (option(argv[i], "1", bench_1))
        continue;
#endif
#ifndef T1HA2_DISABLED
      if (option(argv[i], "2", bench_2))
        continue;
#endif
      if (option(argv[i], "le", bench_le))
        continue;
      if (option(argv[i], "be", bench_be))
        continue;
      if (option(argv[i], "32", bench_32))
        continue;
      if (option(argv[i], "64", bench_64))
        continue;
      if (option(argv[i], "tiny", bench_tiny))
        continue;
      if (option(argv[i], "small", bench_small))
        continue;
      if (option(argv[i], "medium", bench_medium))
        continue;
      if (option(argv[i], "large", bench_large))
        continue;
      if (option(argv[i], "huge", bench_huge))
        continue;

      if (strcmp("--help", argv[i]) == 0 || strcmp("-h", argv[i]) == 0) {
        usage();
        return EXIT_SUCCESS;
      } else {
        fprintf(stderr, "%s: unknown option '%s'\n\n", argv[0], argv[i]);
        usage();
        return EXIT_FAILURE;
      }
    }
    if ((option_flags & bench_funcs_flags) == 0)
      option_flags |= (option_flags & hash_stdin_strings)
                          ? bench_2
                          : default_option_flags & bench_funcs_flags;
    if ((option_flags & bench_size_flags) == 0)
      option_flags |= default_option_flags & bench_size_flags;
  } else {
    option_flags = default_option_flags;
    disabled_option_flags = default_disabled_option_flags;
  }

  /*************************************************************************/

  if (!is_option_set(test_quiet))
    print_build_info();

  if (t1ha_selfcheck__all_enabled() != 0) {
    if (is_option_set(test_quiet))
      print_build_info();
    puts(" - SELF-CHECK FAILED!\n"
         " - PLEASE report this troubleful compiler version and options\n"
         "   at https://github.com/leo-yuriev/t1ha/issues/26\n");
    return EXIT_FAILURE;
  } else if (!is_option_set(test_quiet))
    puts(" (self-check passed)");

  bool failed = false;
#ifndef T1HA2_DISABLED
  /* Stable t1ha2 */
  failed |= verify("t1ha2_atonce", t1ha2_atonce, t1ha_refval_2atonce);
  failed |=
      verify("t1ha2_atonce128", thunk_t1ha2_atonce128, t1ha_refval_2atonce128);
  failed |= verify("t1ha2_stream", thunk_t1ha2_stream, t1ha_refval_2stream);
  failed |=
      verify("t1ha2_stream128", thunk_t1ha2_stream128, t1ha_refval_2stream128);
#endif
#ifndef T1HA1_DISABLED
  /* Stable t1ha1 */
  failed |= verify("t1ha1_64le", t1ha1_le, t1ha_refval_64le);
  failed |= verify("t1ha1_64be", t1ha1_be, t1ha_refval_64be);
#endif
#ifndef T1HA0_DISABLED
  failed |= verify("t1ha0_32le", t1ha0_32le, t1ha_refval_32le);
  failed |= verify("t1ha0_32be", t1ha0_32be, t1ha_refval_32be);
#if T1HA0_AESNI_AVAILABLE
#ifdef __e2k__
  failed |=
      verify("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, refval_ia32aes_a);
  failed |= verify("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, refval_ia32aes_a);
#else
  ia32_fetch_cpu_features();
  if (ia32_cpu_features.basic.ecx & UINT32_C(0x02000000)) {
    failed |= verify("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx,
                     t1ha_refval_ia32aes_a);
    if ((ia32_cpu_features.basic.ecx & UINT32_C(0x1A000000)) ==
        UINT32_C(0x1A000000)) {
      failed |=
          verify("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, t1ha_refval_ia32aes_a);
      if (ia32_cpu_features.extended_7.ebx & 32)
        failed |= verify("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2,
                         t1ha_refval_ia32aes_b);
    }
  } else {
    if (option_flags & user_wanna_aes)
      printf(" - AES-NI not available on the current CPU\n");
    option_flags &= ~bench_aes;
  }
  if ((ia32_cpu_features.basic.ecx & UINT32_C(0x1A000000)) !=
      UINT32_C(0x1A000000))
    option_flags &= ~bench_avx;
  if ((ia32_cpu_features.extended_7.ebx & 32) == 0)
    option_flags &= ~bench_avx2;
#endif
#endif /* T1HA0_AESNI_AVAILABLE */
#endif /* T1HA0_DISABLED */

  failed |= HighwayHash64_verify(HighwayHash64_pure_c, "HighwayHash64_pure_c");
  failed |= HighwayHash64_verify(HighwayHash64_Portable,
                                 "HighwayHash64_portable_cxx");
#ifdef __ia32__
  if (ia32_cpu_features.basic.ecx & (1ul << 19))
    HighwayHash64_verify(HighwayHash64_SSE41, "HighwayHash64_sse41");
  if (ia32_cpu_features.extended_7.ebx & 32)
    HighwayHash64_verify(HighwayHash64_AVX2, "HighwayHash64_avx2");
#endif
#ifdef __e2k__
  HighwayHash64_verify(HighwayHash64_SSE41, "HighwayHash64_sse41");
#endif

  failed |= verify("StadtX", thunk_StadtX, refval_StadtX);

  if (failed)
    return EXIT_FAILURE;

  /*************************************************************************/

  if (is_option_set(hash_stdin_strings)) {
    uint64_t (*hash_function)(const void *data, size_t length, uint64_t seed) =
        NULL;
    const char *hash_name = NULL;

    if (is_selected(bench_highwayhash)) {
      hash_function = thunk_HighwayHash64_pure_c;
      hash_name = "HighwayHash64";
    } else if (is_selected(bench_64 | bench_xxhash)) {
      hash_function = XXH64;
      hash_name = "xxhash64";
    } else if (is_selected(bench_32 | bench_xxhash)) {
      hash_function = thunk_XXH32;
      hash_name = "xxhash32";
    } else if (is_selected(bench_64 | bench_stadtx)) {
      hash_function = thunk_StadtX;
      hash_name = "StadtX";
#ifndef T1HA2_DISABLED
    } else if (is_selected(bench_64 | bench_2)) {
      hash_function = t1ha2_atonce;
      hash_name = "t1ha2_atonce";
#endif
#ifndef T1HA1_DISABLED
    } else if (is_selected(bench_64 | bench_le | bench_1)) {
      hash_function = t1ha1_le;
      hash_name = "t1ha1_le";
    } else if (is_selected(bench_64 | bench_be | bench_1)) {
      hash_function = t1ha1_be;
      hash_name = "t1ha1_be";
#endif
#ifndef T1HA0_DISABLED
    } else if (is_selected(bench_32 | bench_le | bench_0)) {
      hash_function = t1ha0_32le;
      hash_name = "t1ha0_32le";
    } else if (is_selected(bench_32 | bench_be | bench_0)) {
      hash_function = t1ha0_32be;
      hash_name = "t1ha0_32be";
    } else if (is_selected(bench_0)) {
      hash_function = t1ha0;
      hash_name = "t1ha0";
#endif
    } else if (is_selected(bench_xxhash)) {
      hash_function = XXH64;
      hash_name = "xxhash64";
    } else {
      fprintf(stderr, "hash-function should be selected explicitly\n");
      return EXIT_FAILURE;
    }

    size_t buffer_size =
#if defined(_POSIX2_LINE_MAX)
        _POSIX2_LINE_MAX
#elif defined(LINE_MAX)
        LINE_MAX
#else
        4096
#endif
        ;

    char *buffer = malloc(buffer_size);
    if (!buffer) {
      perror("malloc()");
      return EXIT_FAILURE;
    }

    if (1 > printf("# %s '--hash-stdin' using %s()\n", argv[0], hash_name)) {
      perror("printf(stdout)");
      return EXIT_FAILURE;
    }

    while (!feof(stdin)) {
#if (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L) ||                \
    (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 700)
      ssize_t bytes = getline(&buffer, &buffer_size, stdin);
      if (bytes < 0) {
        if (feof(stdin))
          break;
        perror("getline(stdin)");
        return EXIT_FAILURE;
      }
#else
      if (!fgets(buffer, (int)buffer_size, stdin)) {
        if (feof(stdin))
          break;
        perror("fgets(stdin)");
        return EXIT_FAILURE;
      }
      size_t bytes = strlen(buffer);
#endif

      if (1 > printf("%016" PRIx64 "\n",
                     hash_function(buffer, bytes, 42 /* seed */))) {
        perror("printf(stdout)");
        return EXIT_FAILURE;
      }
    }

    free(buffer);
    return EXIT_SUCCESS;
  }

  /*************************************************************************/

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
  printf("%g %s%s, %g iteration%s/%s\n", mats, mera.units,
         (mats > 1.5) ? "s" : "", 1 / mats, (1 / mats > 1.5) ? "s" : "",
         mera.units);

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

#if !defined(__OPTIMIZE__) && (defined(_MSC_VER) && defined(_DEBUG))
  bench_size(1, "Non-optimized/Debug");
  printf("\nNon-optimized/Debug build, skip benchmark\n");
#else
  if (is_option_set(bench_tiny))
    bench_size(7, "tiny");
  if (is_option_set(bench_small))
    bench_size(63, "small");
  if (is_option_set(bench_medium))
    bench_size(1024, "medium");
  if (is_option_set(bench_large))
    bench_size(1024 * 16, "large");
  if (is_option_set(bench_huge))
    bench_size(1024 * 256, "huge");
#endif /* __OPTIMIZE__ */

  return EXIT_SUCCESS;
}
