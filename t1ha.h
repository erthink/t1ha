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

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#pragma once
#if defined(__cplusplus) && __cplusplus >= 201103L
#include <climits>
#include <cstddef>
#include <cstdint>
#else
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#endif

/*****************************************************************************/

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) ||           \
    !defined(__ORDER_BIG_ENDIAN__)

#if defined(__GLIBC__) || defined(__GNU_LIBRARY__) || defined(__ANDROID__)
#include <endian.h>
#elif defined(__APPLE__) || defined(__MACH__) || defined(__OpenBSD__)
#include <machine/endian.h>
#elif defined(__bsdi__) || defined(__DragonFly__) || defined(__FreeBSD__) ||   \
    defined(__NETBSD__) || defined(__NetBSD__)
#include <sys/param.h>
#endif /* OS */

#if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
#define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
#define __BYTE_ORDER__ __BYTE_ORDER
#elif defined(_BYTE_ORDER) && defined(_LITTLE_ENDIAN) && defined(_BIG_ENDIAN)
#define __ORDER_LITTLE_ENDIAN__ _LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ _BIG_ENDIAN
#define __BYTE_ORDER__ _BYTE_ORDER
#else
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321

#if defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN) ||                   \
    defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) ||    \
    defined(__MIPSEL__) || defined(_MIPSEL) || defined(__MIPSEL) ||            \
    defined(_M_ARM) || defined(_M_ARM64) || defined(__e2k__) ||                \
    defined(__elbrus_4c__) || defined(__elbrus_8c__) || defined(__bfin__) ||   \
    defined(__BFIN__) || defined(__ia64__) || defined(_IA64) ||                \
    defined(__IA64__) || defined(__ia64) || defined(_M_IA64) ||                \
    defined(__itanium__) || defined(i386) || defined(__i386__) ||              \
    defined(__i486__) || defined(__i586__) || defined(__i686__) ||             \
    defined(__i386) || defined(_M_IX86) || defined(_X86_) ||                   \
    defined(__THW_INTEL__) || defined(__I86__) || defined(__INTEL__) ||        \
    defined(__x86_64) || defined(__x86_64__) || defined(__amd64__) ||          \
    defined(__amd64) || defined(_M_X64) || defined(_WIN32) ||                  \
    defined(_WIN64) || defined(__WIN32__) || defined(__TOS_WIN__) ||           \
    defined(__WINDOWS__)
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__

#elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN) || defined(__ARMEB__) || \
    defined(__THUMBEB__) || defined(__AARCH64EB__) || defined(__MIPSEB__) ||   \
    defined(_MIPSEB) || defined(__MIPSEB) defined(__m68k__) ||                 \
    defined(M68000) || defined(__hppa__) || defined(__hppa) ||                 \
    defined(__HPPA__) || defined(__sparc__) || defined(__sparc) ||             \
    defined(__370__) || defined(__THW_370__) || defined(__s390__) ||           \
    defined(__s390x__) || defined(__SYSC_ZARCH__)
#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__

#else
#error __BYTE_ORDER__ should be defined.
#endif /* Arch */

#endif
#endif /* __BYTE_ORDER__ || __ORDER_LITTLE_ENDIAN__ || __ORDER_BIG_ENDIAN__ */

/*****************************************************************************/

#ifndef __has_attribute
#define __has_attribute(x) (0)
#endif

#ifndef __GNUC_PREREQ
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define __GNUC_PREREQ(maj, min)                                                \
  ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define __GNUC_PREREQ(maj, min) 0
#endif
#endif /* __GNUC_PREREQ */

#ifndef __CLANG_PREREQ
#ifdef __clang__
#define __CLANG_PREREQ(maj, min)                                               \
  ((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
#else
#define __CLANG_PREREQ(maj, min) (0)
#endif
#endif /* __CLANG_PREREQ */

#ifndef __dll_export
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(__GNUC__) || __has_attribute(dllexport)
#define __dll_export __attribute__((dllexport))
#elif defined(_MSC_VER)
#define __dll_export __declspec(dllexport)
#else
#define __dll_export
#endif
#elif defined(__GNUC__) || __has_attribute(visibility)
#define __dll_export __attribute__((visibility("default")))
#else
#define __dll_export
#endif
#endif /* __dll_export */

#ifndef __dll_import
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(__GNUC__) || __has_attribute(dllimport)
#define __dll_import __attribute__((dllimport))
#elif defined(_MSC_VER)
#define __dll_import __declspec(dllimport)
#else
#define __dll_import
#endif
#else
#define __dll_import
#endif
#endif /* __dll_import */

#if defined(t1ha_EXPORTS)
#define T1HA_API __dll_export
#elif defined(t1ha_IMPORTS)
#define T1HA_API __dll_import
#else
#define T1HA_API
#endif /* T1HA_API */

#if defined(i386) || defined(__i386__) || defined(__i486__) ||                 \
    defined(__i586__) || defined(__i686__) || defined(__i386) ||               \
    defined(_M_IX86) || defined(_X86_) || defined(__THW_INTEL__) ||            \
    defined(__I86__) || defined(__INTEL__) || defined(__x86_64) ||             \
    defined(__x86_64__) || defined(__amd64__) || defined(__amd64) ||           \
    defined(_M_X64)
#define T1HA_IA32_AVAILABLE 1
#else
#define T1HA_IA32_AVAILABLE 0
#endif /* x86 */

#if defined(_M_IX86) || defined(_M_X64)
#define T1HA_ALIGN_PREFIX __declspec(align(32)) /* required only for SIMD */
#else
#define T1HA_ALIGN_PREFIX
#endif /* _MSC_VER */

#if defined(__GNUC__) && T1HA_IA32_AVAILABLE
#define T1HA_ALIGN_SUFFIX                                                      \
  __attribute__((aligned(32))) /* required only for SIMD */
#else
#define T1HA_ALIGN_SUFFIX
#endif /* GCC x86 */

#ifdef __cplusplus
extern "C" {
#endif

typedef union T1HA_ALIGN_PREFIX t1ha_state256 {
  uint8_t bytes[32];
  uint32_t u32[8];
  uint64_t u64[4];
  struct {
    uint64_t a, b, c, d;
  } n;
} t1ha_state256_t T1HA_ALIGN_SUFFIX;

typedef struct t1ha_context {
  t1ha_state256_t state;
  t1ha_state256_t buffer;
  size_t partial;
  uint64_t total;
} t1ha_context_t;

T1HA_API uint64_t t1ha2_atonce(const void *data, size_t length, uint64_t seed);

T1HA_API uint64_t t1ha2_atonce128(uint64_t *__restrict extra_result,
                                  const void *__restrict data, size_t length,
                                  uint64_t seed);

T1HA_API void t1ha2_init(t1ha_context_t *ctx, uint64_t seed_x, uint64_t seed_y);
T1HA_API void t1ha2_update(t1ha_context_t *__restrict ctx,
                           const void *__restrict data, size_t length);

T1HA_API uint64_t t1ha2_final(t1ha_context_t *__restrict ctx,
                              uint64_t *__restrict extra_result);

/* The legacy low-endian version.
 *  - runs faster on 64-bit low-endian platforms,
 *    in other cases may runs slowly.
 *  - returns same result on all architectures and CPUs,
 *    but it is differs from t1ha0().
 *  - unfortunately it fails the "strict avalanche criteria",
 *    see test results at https://github.com/demerphq/smhasher. */
T1HA_API uint64_t t1ha1_le(const void *data, size_t length, uint64_t seed);

/* The big-endian legacy version.
 *  - runs faster on 64-bit big-endian platforms,
 *    in other cases may runs slowly.
 *  - returns same result on all architectures and CPUs,
 *    but it is differs from t1ha0().
 *  - unfortunately it fails the "strict avalanche criteria",
 *    see test results at https://github.com/demerphq/smhasher. */
T1HA_API uint64_t t1ha1_be(const void *data, size_t length, uint64_t seed);

/* The nicname for generic legacy version of "Fast Positive Hash".
 *  - returns same result on all architectures and CPUs.
 *  - created for 64-bit little-endian platforms,
 *    in other cases may runs slowly.
 *  - unfortunately it fails the "strict avalanche criteria",
 *    see test results at https://github.com/demerphq/smhasher. */
static __inline uint64_t t1ha(const void *data, size_t length, uint64_t seed) {
  return t1ha1_le(data, length, seed);
}

/* t1ha0() is a facade that selects most quick-and-dirty hash
 * for the current processor.
 *
 * BE CAREFUL!!!  This is means:
 *
 *   1. The quality of hash is a subject for tradeoffs with performance.
 *      So, the quality and strength of t1ha0() may be lower than t1ha1(),
 *      especially on 32-bit targets, but then much faster.
 *      However, guaranteed that it passes all SMHasher tests.
 *
 *   2. No warranty that the hash result will be same for particular
 *      key on another machine or another version of libt1ha.
 *
 *      Briefly, such hash-results and their derivatives, should be
 *      used only in runtime, but should not be persist or transferred
 *      over a network. */

uint64_t t1ha0_32le(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_32be(const void *data, size_t length, uint64_t seed);

#if T1HA_IA32_AVAILABLE && (!defined(_M_IX86) || _MSC_VER > 1800)
#define T1HA0_AESNI_AVAILABLE
#define T1HA0_RUNTIME_SELECT
uint64_t t1ha0_ia32aes_noavx(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx2(const void *data, size_t length, uint64_t seed);
#endif /* T1HA_IA32_AVAILABLE */

#ifdef T1HA0_RUNTIME_SELECT
#ifdef __ELF__
T1HA_API uint64_t t1ha0(const void *data, size_t length, uint64_t seed);
#else
T1HA_API extern uint64_t (*t1ha0_funcptr)(const void *data, size_t length,
                                          uint64_t seed);
static __inline uint64_t t1ha0(const void *data, size_t length, uint64_t seed) {
  return t1ha0_funcptr(data, length, seed);
}
#endif /* __ELF__ */

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static __inline uint64_t t1ha0(const void *data, size_t length, uint64_t seed) {
#if UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul
  return t1ha1_be(data, length, seed);
#else
  return t1ha0_32be(data, length, seed);
#endif
}
#else
static __inline uint64_t t1ha0(const void *data, size_t length, uint64_t seed) {
#if UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul
  return t1ha1_le(data, length, seed);
#else
  return t1ha0_32le(data, length, seed);
#endif
}
#endif /* !T1HA0_RUNTIME_SELECT */

#ifdef __cplusplus
}
#endif
