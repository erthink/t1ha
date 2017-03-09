/*
 *  Copyright (c) 2016-2017 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2017 Leonid Yuriev <leo@yuriev.ru>,
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
 *     but without penalties could runs on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others which are not use specific hardware tricks.
 *  3. Not suitable for cryptography.
 *
 * The Future will Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

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
#endif /* fptu_EXPORTS */

#ifdef __cplusplus
extern "C" {
#endif

/* The main low-endian version.
 *  - runs faster on 64-bit low-endian platforms,
 *    in other cases may runs slowly.
 *  - returns same result on all architectures and CPUs,
 *    but it is differs from t1ha(). */
T1HA_API uint64_t t1ha1_le(const void *data, size_t len, uint64_t seed);

/* The big-endian version.
 *  - runs faster on 64-bit big-endian platforms,
 *    in other cases may runs slowly.
 *  - returns same result on all architectures and CPUs,
 *    but it is differs from t1ha(). */
T1HA_API uint64_t t1ha1_be(const void *data, size_t len, uint64_t seed);

/* The nicname for generic version of "Fast Positive Hash".
 *  - returns same result on all architectures and CPUs.
 *  - created for 64-bit little-endian platforms,
 *    in other cases may runs slowly. */
static __inline uint64_t t1ha(const void *data, size_t len, uint64_t seed) {
  return t1ha1_le(data, len, seed);
}

/* t1ha0() is a facade that selects most quick-and-dirty hash
 * for the current processor.
 *
 * BE CAREFUL!!!  This is means:
 *
 *   1. The quality of hash is a subject for tradeoffs with performance
 *      and may be lower than t1ha1(), especially on 32-bit targets.
 *      However, guaranteed that it passes all SMHasher tests.
 *
 *   2. No warranty that the hash result will be same for particular
 *      key on another machine or another version of libt1ha.
 *
 *      Briefly, such hash-results and their derivatives, should be
 *      used only in runtime, but should not be persist or transferred
 *      over a network. */

#ifdef __ELF__
T1HA_API uint64_t t1ha0(const void *data, size_t len, uint64_t seed);
#else
T1HA_API extern uint64_t (*_t1ha0_ptr)(const void *data, size_t len,
                                       uint64_t seed);
static __inline uint64_t t1ha0(const void *data, size_t len, uint64_t seed) {
  return _t1ha0_ptr(data, len, seed);
}
#endif /* __ELF__ */

#ifdef T1HA_TESTING
uint64_t _t1ha_32le(const void *data, size_t len, uint64_t seed);
uint64_t _t1ha_32be(const void *data, size_t len, uint64_t seed);

#if ((defined(__AES__) || __GNUC_PREREQ(4, 4) || __has_attribute(target)) &&   \
     (defined(__x86_64__) || defined(__i386__))) ||                            \
    defined(_M_X64) || defined(_M_IX86)
uint64_t _t1ha_ia32aes(const void *data, size_t len, uint64_t seed);
#endif /* __AES__ */

#endif /* T1HA_TESTING */

#ifdef __cplusplus
}
#endif
