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
#ifndef T1HA_USE_FAST_ONESHOT_READ

/* Define it to 1 for little bit faster code.
 * Unfortunately this may triggering a false-positive alarms from Valgrind,
 * AddressSanitizer and other similar tool.
 * So, define it to 0 for calmness if doubt. */
#define T1HA_USE_FAST_ONESHOT_READ 1

#endif /* T1HA_USE_FAST_ONESHOT_READ */

/*****************************************************************************/

#include <string.h> /* for memcpy() */

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) ||           \
    !defined(__ORDER_BIG_ENDIAN__)
#ifndef _MSC_VER
#include <sys/param.h> /* for endianness */
#endif
#if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
#define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
#define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
#define __BYTE_ORDER__ __BYTE_ORDER
#else
#define __ORDER_LITTLE_ENDIAN__ 1234
#define __ORDER_BIG_ENDIAN__ 4321
#if defined(__LITTLE_ENDIAN__) || defined(_LITTLE_ENDIAN) ||                   \
    defined(__ARMEL__) || defined(__THUMBEL__) || defined(__AARCH64EL__) ||    \
    defined(__MIPSEL__) || defined(_MIPSEL) || defined(__MIPSEL) ||            \
    defined(__i386) || defined(__x86_64__) || defined(_M_IX86) ||              \
    defined(_M_X64) || defined(i386) || defined(_X86_) || defined(__i386__) || \
    defined(_X86_64_) || defined(_M_ARM) || defined(_M_ARM64) ||               \
    defined(__e2k__)
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#elif defined(__BIG_ENDIAN__) || defined(_BIG_ENDIAN) || defined(__ARMEB__) || \
    defined(__THUMBEB__) || defined(__AARCH64EB__) || defined(__MIPSEB__) ||   \
    defined(_MIPSEB) || defined(__MIPSEB) || defined(_M_IA64)
#define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__
#else
#error __BYTE_ORDER__ should be defined.
#endif
#endif
#endif /* __BYTE_ORDER__ || __ORDER_LITTLE_ENDIAN__ || __ORDER_BIG_ENDIAN__ */

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ &&                               \
    __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__
#error Unsupported byte order.
#endif

#if !defined(UNALIGNED_OK)
#if defined(__i386) || defined(__x86_64__) || defined(_M_IX86) ||              \
    defined(_M_X64) || defined(i386) || defined(_X86_) || defined(__i386__) || \
    defined(_X86_64_)
#define UNALIGNED_OK 1
#define PAGESIZE 4096
#else
#define UNALIGNED_OK 0
#endif
#endif

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#if __GNUC_PREREQ(4, 4) || defined(__clang__)

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#include <x86intrin.h>
#endif
#define likely(cond) __builtin_expect(!!(cond), 1)
#define unlikely(cond) __builtin_expect(!!(cond), 0)
#if __GNUC_PREREQ(4, 5) || defined(__clang__)
#define unreachable() __builtin_unreachable()
#endif
#define bswap64(v) __builtin_bswap64(v)
#define bswap32(v) __builtin_bswap32(v)
#if __GNUC_PREREQ(4, 8) || __has_builtin(__builtin_bswap16)
#define bswap16(v) __builtin_bswap16(v)
#endif
#if __GNUC_PREREQ(4, 3) || __has_attribute(unused)
#define maybe_unused __attribute__((unused))
#endif

#elif defined(_MSC_VER)

#if _MSC_FULL_VER < 190024218 && defined(_M_IX86)
#pragma message(                                                               \
    "For AES-NI at least \"Microsoft C/C++ Compiler\" version 19.00.24218 (Visual Studio 2015 Update 5) is required.")
#endif
#if _MSC_FULL_VER < 191025019
#pragma message(                                                               \
    "It is recommended to use \"Microsoft C/C++ Compiler\" version 19.10.25019 (Visual Studio 2017) or newer.")
#endif
#if _MSC_FULL_VER < 180040629
#error At least "Microsoft C/C++ Compiler" version 18.00.40629 (Visual Studio 2013 Update 5) is required.
#endif

#pragma warning(push, 1)

#include <intrin.h>
#include <stdlib.h>
#define likely(cond) (cond)
#define unlikely(cond) (cond)
#define unreachable() __assume(0)
#define bswap64(v) _byteswap_uint64(v)
#define bswap32(v) _byteswap_ulong(v)
#define bswap16(v) _byteswap_ushort(v)
#define rot64(v, s) _rotr64(v, s)
#define rot32(v, s) _rotr(v, s)
#define __inline __forceinline

#if defined(_M_ARM64) || defined(_M_X64) || defined(_M_IA64)
#pragma intrinsic(_umul128)
#define mul_64x64_128(a, b, ph) _umul128(a, b, ph)
#pragma intrinsic(__umulh)
#define mul_64x64_high(a, b) __umulh(a, b)
#endif

#if defined(_M_IX86)
#pragma intrinsic(__emulu)
#define mul_32x32_64(a, b) __emulu(a, b)
#elif defined(_M_ARM)
#define mul_32x32_64(a, b) _arm_umull(a, b)
#endif

#pragma warning(pop)
#pragma warning(disable : 4514) /* 'xyz': unreferenced inline function         \
                                   has been removed */
#pragma warning(disable : 4710) /* 'xyz': function not inlined */
#pragma warning(disable : 4711) /* function 'xyz' selected for                 \
                                   automatic inline expansion */
#pragma warning(disable : 4127) /* conditional expression is constant */
#pragma warning(disable : 4702) /* unreachable code */
#endif                          /* Compiler */

#ifndef likely
#define likely(cond) (cond)
#endif
#ifndef unlikely
#define unlikely(cond) (cond)
#endif
#ifndef maybe_unused
#define maybe_unused
#endif
#ifndef unreachable
#define unreachable()                                                          \
  do {                                                                         \
  } while (1)
#endif

#ifndef bswap64
#if defined(bswap_64)
#define bswap64 bswap_64
#elif defined(__bswap_64)
#define bswap64 __bswap_64
#else
static __inline uint64_t bswap64(uint64_t v) {
  return v << 56 | v >> 56 | ((v << 40) & UINT64_C(0x00ff000000000000)) |
         ((v << 24) & UINT64_C(0x0000ff0000000000)) |
         ((v << 8) & UINT64_C(0x000000ff00000000)) |
         ((v >> 8) & UINT64_C(0x00000000ff000000)) |
         ((v >> 24) & UINT64_C(0x0000000000ff0000)) |
         ((v >> 40) & UINT64_C(0x000000000000ff00));
}
#endif
#endif /* bswap64 */

#ifndef bswap32
#if defined(bswap_32)
#define bswap32 bswap_32
#elif defined(__bswap_32)
#define bswap32 __bswap_32
#else
static __inline uint32_t bswap32(uint32_t v) {
  return v << 24 | v >> 24 | ((v << 8) & UINT32_C(0x00ff0000)) |
         ((v >> 8) & UINT32_C(0x0000ff00));
}
#endif
#endif /* bswap32 */

#ifndef bswap16
#if defined(bswap_16)
#define bswap16 bswap_16
#elif defined(__bswap_16)
#define bswap16 __bswap_16
#else
static __inline uint16_t bswap16(uint16_t v) { return v << 8 | v >> 8; }
#endif
#endif /* bswap16 */

/***************************************************************************/

static __inline uint64_t fetch64_le(const void *v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return *(const uint64_t *)v;
#else
  return bswap64(*(const uint64_t *)v);
#endif
}

static __inline uint32_t fetch32_le(const void *v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return *(const uint32_t *)v;
#else
  return bswap32(*(const uint32_t *)v);
#endif
}

static __inline uint16_t fetch16_le(const void *v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return *(const uint16_t *)v;
#else
  return bswap16(*(const uint16_t *)v);
#endif
}

#if T1HA_USE_FAST_ONESHOT_READ && UNALIGNED_OK && defined(PAGESIZE) &&         \
    PAGESIZE > 0
#define can_read_underside(ptr, size)                                          \
  ((size) <= sizeof(uintptr_t) && ((PAGESIZE - (size)) & (uintptr_t)(ptr)) != 0)
#endif /* can_fast_read */

static __inline uint64_t tail64_le(const void *v, size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
#ifdef can_read_underside
  /* On some systems (e.g. x86) we can perform a 'oneshot' read, which
   * is little bit faster. Thanks Marcin Żukowski <marcin.zukowski@gmail.com>
   * for the reminder. */
  const unsigned offset = (8 - tail) & 7;
  const unsigned shift = offset << 3;
  if (likely(can_read_underside(p, 8))) {
    p -= offset;
    return fetch64_le(p) >> shift;
  }
  return fetch64_le(p) & ((~UINT64_C(0)) >> shift);
#endif /* 'oneshot' read */

  uint64_t r = 0;
  switch (tail & 7) {
#if UNALIGNED_OK && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 0:
    return fetch64_le(p);
  case 7:
    r = (uint64_t)p[6] << 8;
  /* fall through */
  case 6:
    r += p[5];
    r <<= 8;
  /* fall through */
  case 5:
    r += p[4];
    r <<= 32;
  /* fall through */
  case 4:
    return r + fetch32_le(p);
  case 3:
    r = (uint64_t)p[2] << 16;
  /* fall through */
  case 2:
    return r + fetch16_le(p);
  case 1:
    return p[0];
#else
  /* For most CPUs this code is better than a
   * copying for alignment and/or byte reordering. */
  case 0:
    r = p[7] << 8;
  /* fall through */
  case 7:
    r += p[6];
    r <<= 8;
  /* fall through */
  case 6:
    r += p[5];
    r <<= 8;
  /* fall through */
  case 5:
    r += p[4];
    r <<= 8;
  /* fall through */
  case 4:
    r += p[3];
    r <<= 8;
  /* fall through */
  case 3:
    r += p[2];
    r <<= 8;
  /* fall through */
  case 2:
    r += p[1];
    r <<= 8;
  /* fall through */
  case 1:
    return r + p[0];
#endif
  }
  unreachable();
}

static maybe_unused __inline uint64_t fetch64_be(const void *v) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return *(const uint64_t *)v;
#else
  return bswap64(*(const uint64_t *)v);
#endif
}

static maybe_unused __inline uint32_t fetch32_be(const void *v) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return *(const uint32_t *)v;
#else
  return bswap32(*(const uint32_t *)v);
#endif
}

static maybe_unused __inline uint16_t fetch16_be(const void *v) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return *(const uint16_t *)v;
#else
  return bswap16(*(const uint16_t *)v);
#endif
}

static maybe_unused __inline uint64_t tail64_be(const void *v, size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
#ifdef can_read_underside
  /* On some systems we can perform a 'oneshot' read, which is little bit
   * faster. Thanks Marcin Żukowski <marcin.zukowski@gmail.com> for the
   * reminder. */
  const unsigned offset = (8 - tail) & 7;
  const unsigned shift = offset << 3;
  if (likely(can_read_underside(p, 8))) {
    p -= offset;
    return fetch64_be(p) & ((~UINT64_C(0)) >> shift);
  }
  return fetch64_be(p) >> shift;
#endif /* 'oneshot' read */

  switch (tail & 7) {
#if UNALIGNED_OK && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 1:
    return p[0];
  case 2:
    return fetch16_be(p);
  case 3:
    return (uint32_t)fetch16_be(p) << 8 | p[2];
  case 4:
    return fetch32_be(p);
  case 5:
    return (uint64_t)fetch32_be(p) << 8 | p[4];
  case 6:
    return (uint64_t)fetch32_be(p) << 16 | fetch16_be(p + 4);
  case 7:
    return (uint64_t)fetch32_be(p) << 24 | (uint32_t)fetch16_be(p + 4) << 8 |
           p[6];
  case 0:
    return fetch64_be(p);
#else
  /* For most CPUs this code is better than a
   * copying for alignment and/or byte reordering. */
  case 1:
    return p[0];
  case 2:
    return p[1] | (uint32_t)p[0] << 8;
  case 3:
    return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
  case 4:
    return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
           (uint32_t)p[0] << 24;
  case 5:
    return p[4] | (uint32_t)p[3] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[1] << 24 | (uint64_t)p[0] << 32;
  case 6:
    return p[5] | (uint32_t)p[4] << 8 | (uint32_t)p[3] << 16 |
           (uint32_t)p[2] << 24 | (uint64_t)p[1] << 32 | (uint64_t)p[0] << 40;
  case 7:
    return p[6] | (uint32_t)p[5] << 8 | (uint32_t)p[4] << 16 |
           (uint32_t)p[3] << 24 | (uint64_t)p[2] << 32 | (uint64_t)p[1] << 40 |
           (uint64_t)p[0] << 48;
  case 0:
    return p[7] | (uint32_t)p[6] << 8 | (uint32_t)p[5] << 16 |
           (uint32_t)p[4] << 24 | (uint64_t)p[3] << 32 | (uint64_t)p[2] << 40 |
           (uint64_t)p[1] << 48 | (uint64_t)p[0] << 56;
#endif
  }
  unreachable();
}

/***************************************************************************/

#ifndef rot64
static __inline uint64_t rot64(uint64_t v, unsigned s) {
  return (v >> s) | (v << (64 - s));
}
#endif /* rot64 */

#ifndef mul_32x32_64
static __inline uint64_t mul_32x32_64(uint32_t a, uint32_t b) {
  return a * (uint64_t)b;
}
#endif /* mul_32x32_64 */

#ifndef mul_64x64_128

static maybe_unused __inline unsigned add_with_carry(uint64_t *sum,
                                                     uint64_t addend) {
  *sum += addend;
  return *sum < addend;
}

static maybe_unused __inline uint64_t mul_64x64_128(uint64_t a, uint64_t b,
                                                    uint64_t *h) {
#if defined(__SIZEOF_INT128__) ||                                              \
    (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 128)
  __uint128_t r = (__uint128_t)a * (__uint128_t)b;
  /* modern GCC could nicely optimize this */
  *h = r >> 64;
  return r;
#elif defined(mul_64x64_high)
  *h = mul_64x64_high(a, b);
  return a * b;
#else
  /* performs 64x64 to 128 bit multiplication */
  uint64_t ll = mul_32x32_64((uint32_t)a, (uint32_t)b);
  uint64_t lh = mul_32x32_64(a >> 32, (uint32_t)b);
  uint64_t hl = mul_32x32_64((uint32_t)a, b >> 32);
  *h = mul_32x32_64(a >> 32, b >> 32) + (lh >> 32) + (hl >> 32) +
       /* Few simplification are possible here for 32-bit architectures,
        * but thus we would lost compatibility with the original 64-bit
        * version.  Think is very bad idea, because then 32-bit t1ha will
        * still (relatively) very slowly and well yet not compatible. */
       add_with_carry(&ll, lh << 32) + add_with_carry(&ll, hl << 32);
  return ll;
#endif
}

#endif /* mul_64x64_128() */

#ifndef mul_64x64_high
static maybe_unused __inline uint64_t mul_64x64_high(uint64_t a, uint64_t b) {
  uint64_t h;
  mul_64x64_128(a, b, &h);
  return h;
}
#endif /* mul_64x64_high */

/***************************************************************************/

/* 'magic' primes */
static const uint64_t p0 = UINT64_C(0xEC99BF0D8372CAAB);
static const uint64_t p1 = UINT64_C(0x82434FE90EDCEF39);
static const uint64_t p2 = UINT64_C(0xD4F06DB99D67BE4B);
static const uint64_t p3 = UINT64_C(0xBD9CACC22C6E9571);
static const uint64_t p4 = UINT64_C(0x9C06FAF4D023E3AB);
static const uint64_t p5 = UINT64_C(0xC060724A8424F345);
static const uint64_t p6 = UINT64_C(0xCB5AF53AE3AAAC31);

/* rotations */
static const unsigned s0 = 41;
static const unsigned s1 = 17;
static const unsigned s2 = 31;

/* xor high and low parts of full 128-bit product */
static maybe_unused __inline uint64_t mux64(uint64_t v, uint64_t p) {
  uint64_t l, h;
  l = mul_64x64_128(v, p, &h);
  return l ^ h;
}

/* xor-mul-xor mixer */
static maybe_unused __inline uint64_t mix64(uint64_t v, uint64_t p) {
  v *= p;
  return v ^ rot64(v, s0);
}
