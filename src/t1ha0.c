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

#ifdef _MSC_VER
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif

#include "../t1ha.h"
#include "t1ha_bits.h"

static __inline uint32_t tail32_le(const void *v, size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
  uint32_t r = 0;
  switch (tail & 3) {
#if UNALIGNED_OK && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 0:
    return fetch32_le(p);
  case 3:
    r = (uint32_t)p[2] << 16;
  case 2:
    return r + fetch16_le(p);
  case 1:
    return p[0];
#else
  /* For most CPUs this code is better than a
   * copying for alignment and/or byte reordering. */
  case 0:
    r += p[3];
    r <<= 8;
  case 3:
    r += p[2];
    r <<= 8;
  case 2:
    r += p[1];
    r <<= 8;
  case 1:
    return r + p[0];
#endif
  }
  unreachable();
}

static __inline uint32_t tail32_be(const void *v, size_t tail) {
  const uint8_t *p = (const uint8_t *)v;
  switch (tail & 3) {
#if UNALIGNED_OK && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  /* For most CPUs this code is better when not needed
   * copying for alignment or byte reordering. */
  case 1:
    return p[0];
  case 2:
    return fetch16_be(p);
  case 3:
    return fetch16_be(p) << 8 | p[2];
  case 0:
    return fetch32_be(p);
#else
  /* For most CPUs this code is better than a
   * copying for alignment and/or byte reordering. */
  case 1:
    return p[0];
  case 2:
    return p[1] | (uint32_t)p[0] << 8;
  case 3:
    return p[2] | (uint32_t)p[1] << 8 | (uint32_t)p[0] << 16;
  case 0:
    return p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 |
           (uint32_t)p[0] << 24;
#endif
  }
  unreachable();
}

/***************************************************************************/

#ifndef rot32
static maybe_unused __inline uint32_t rot32(uint32_t v, unsigned s) {
  return (v >> s) | (v << (32 - s));
}
#endif /* rot32 */

static __inline uint64_t remix32(uint32_t a, uint32_t b) {
  a ^= rot32(b, 13);
  uint64_t l = a | (uint64_t)b << 32;
  l *= p0;
  l ^= l >> 41;
  return l;
}

static __inline void mixup32(uint32_t *a, uint32_t *b, uint32_t v, uint32_t p) {
  uint64_t l = mul_32x32_64(*b + v, p);
  *a ^= (uint32_t)l;
  *b += (uint32_t)(l >> 32);
}

/* 32-bit 'magic' primes */
static const uint32_t q0 = 0x92D78269;
static const uint32_t q1 = 0xCA9B4735;
static const uint32_t q2 = 0xA4ABA1C3;
static const uint32_t q3 = 0xF6499843;
static const uint32_t q4 = 0x86F0FD61;
static const uint32_t q5 = 0xCA2DA6FB;
static const uint32_t q6 = 0xC4BB3575;

T1HA_INTERNAL uint64_t _t1ha_32le(const void *data, size_t len, uint64_t seed) {
  uint32_t a = rot32((uint32_t)len, s1) + (uint32_t)seed;
  uint32_t b = (uint32_t)len ^ (uint32_t)(seed >> 32);

  const int need_align = (((uintptr_t)data) & 3) != 0 && !UNALIGNED_OK;
  uint32_t align[4];

  if (unlikely(len > 16)) {
    uint32_t c = ~a;
    uint32_t d = rot32(b, 5);
    const void *detent = (const uint8_t *)data + len - 15;
    do {
      const uint32_t *v = (const uint32_t *)data;
      if (unlikely(need_align))
        v = (const uint32_t *)memcpy(&align, v, 16);

      uint32_t w0 = fetch32_le(v + 0);
      uint32_t w1 = fetch32_le(v + 1);
      uint32_t w2 = fetch32_le(v + 2);
      uint32_t w3 = fetch32_le(v + 3);

      uint32_t c02 = w0 ^ rot32(w2 + c, 11);
      uint32_t d13 = w1 + rot32(w3 + d, s1);
      c ^= rot32(b + w1, 7);
      d ^= rot32(a + w0, 3);
      b = q1 * (c02 + w3);
      a = q0 * (d13 ^ w2);

      data = (const uint32_t *)data + 4;
    } while (likely(data < detent));

    c += a;
    d += b;
    a ^= q6 * (rot32(c, 16) + d);
    b ^= q5 * (c + rot32(d, 16));

    len &= 15;
  }

  const uint8_t *v = (const uint8_t *)data;
  if (unlikely(need_align) && len > 4)
    v = (const uint8_t *)memcpy(&align, v, len);

  switch (len) {
  default:
    mixup32(&a, &b, fetch32_le(v), q4);
    v += 4;
  case 12:
  case 11:
  case 10:
  case 9:
    mixup32(&b, &a, fetch32_le(v), q3);
    v += 4;
  case 8:
  case 7:
  case 6:
  case 5:
    mixup32(&a, &b, fetch32_le(v), q2);
    v += 4;
  case 4:
  case 3:
  case 2:
  case 1:
    mixup32(&b, &a, tail32_le(v, len), q1);
  case 0:
    return remix32(a, b);
  }
}

T1HA_INTERNAL uint64_t _t1ha_32be(const void *data, size_t len, uint64_t seed) {
  uint32_t a = rot32((uint32_t)len, s1) + (uint32_t)seed;
  uint32_t b = (uint32_t)len ^ (uint32_t)(seed >> 32);

  const int need_align = (((uintptr_t)data) & 3) != 0 && !UNALIGNED_OK;
  uint32_t align[4];

  if (unlikely(len > 16)) {
    uint32_t c = ~a;
    uint32_t d = rot32(b, 5);
    const void *detent = (const uint8_t *)data + len - 15;
    do {
      const uint32_t *v = (const uint32_t *)data;
      if (unlikely(need_align))
        v = (const uint32_t *)memcpy(&align, v, 16);

      uint32_t w0 = fetch32_be(v + 0);
      uint32_t w1 = fetch32_be(v + 1);
      uint32_t w2 = fetch32_be(v + 2);
      uint32_t w3 = fetch32_be(v + 3);

      uint32_t c02 = w0 ^ rot32(w2 + c, 11);
      uint32_t d13 = w1 + rot32(w3 + d, s1);
      c ^= rot32(b + w1, 7);
      d ^= rot32(a + w0, 3);
      b = q1 * (c02 + w3);
      a = q0 * (d13 ^ w2);

      data = (const uint32_t *)data + 4;
    } while (likely(data < detent));

    c += a;
    d += b;
    a ^= q6 * (rot32(c, 16) + d);
    b ^= q5 * (c + rot32(d, 16));

    len &= 15;
  }

  const uint8_t *v = (const uint8_t *)data;
  if (unlikely(need_align) && len > 4)
    v = (const uint8_t *)memcpy(&align, v, len);

  switch (len) {
  default:
    mixup32(&a, &b, fetch32_be(v), q4);
    v += 4;
  case 12:
  case 11:
  case 10:
  case 9:
    mixup32(&b, &a, fetch32_be(v), q3);
    v += 4;
  case 8:
  case 7:
  case 6:
  case 5:
    mixup32(&a, &b, fetch32_be(v), q2);
    v += 4;
  case 4:
  case 3:
  case 2:
  case 1:
    mixup32(&b, &a, tail32_be(v, len), q1);
  case 0:
    return remix32(a, b);
  }
}

/***************************************************************************/

#if defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) ||              \
    defined(i386) || defined(_X86_) || defined(__i386__) || defined(_X86_64_)
static uint32_t x86_cpu_features(void) {
#ifdef __GNUC__
  uint32_t eax, ebx, ecx, edx;
  if (__get_cpuid_max(0, NULL) < 1)
    return 0;
  __cpuid_count(1, 0, eax, ebx, ecx, edx);
  return ecx;
#elif defined(_MSC_VER)
  int info[4];
  __cpuid(info, 0);
  if (info[0] < 1)
    return 0;
  __cpuidex(info, 1, 0);
  return info[2];
#else
  return 0;
#endif
}
#endif

#undef T1HA_ia32aes_AVAILABLE
#if defined(_X86_64_) || defined(__x86_64__) || defined(_M_X64) ||             \
    ((defined(__i386__) || defined(_M_IX86) || defined(i386) ||                \
      defined(_X86_)) &&                                                       \
     (!defined(_MSC_VER) || (_MSC_VER >= 1900)))

#define T1HA_ia32aes_AVAILABLE
#include <emmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#if defined(__x86_64__) && defined(__ELF__) &&                                 \
    (__GNUC_PREREQ(4, 6) || __has_attribute(ifunc)) && __has_attribute(target)
T1HA_INTERNAL uint64_t _t1ha_ia32aes(const void *data, size_t len,
                                     uint64_t seed)
    __attribute__((ifunc("t1ha_aes_resolve")));

static uint64_t t1ha_ia32aes_avx(const void *data, size_t len, uint64_t seed);
static uint64_t t1ha_ia32aes_noavx(const void *data, size_t len, uint64_t seed);

static uint64_t (*t1ha_aes_resolve(void))(const void *, size_t, uint64_t) {
  uint32_t features = x86_cpu_features();
  if ((features & 0x01A000000) == 0x01A000000)
    return t1ha_ia32aes_avx;
  return t1ha_ia32aes_noavx;
}

static uint64_t __attribute__((target("aes,avx")))
t1ha_ia32aes_avx(const void *data, size_t len, uint64_t seed) {
  uint64_t a = seed;
  uint64_t b = len;

  if (unlikely(len > 32)) {
    __m128i x = _mm_set_epi64x(a, b);
    __m128i y = _mm_aesenc_si128(x, _mm_set_epi64x(p0, p1));

    const __m128i *v = (const __m128i *)data;
    const __m128i *const detent =
        (const __m128i *)((const uint8_t *)data + (len & ~15ul));
    data = detent;

    if (len & 16) {
      x = _mm_add_epi64(x, _mm_loadu_si128(v++));
      y = _mm_aesenc_si128(x, y);
    }
    len &= 15;

    if (v + 7 < detent) {
      __m128i salt = y;
      do {
        __m128i t = _mm_aesenc_si128(_mm_loadu_si128(v++), salt);
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));

        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));

        salt = _mm_add_epi64(salt, _mm_set_epi64x(p2, p3));
        t = _mm_aesenc_si128(x, t);
        x = _mm_add_epi64(y, x);
        y = t;
      } while (v + 7 < detent);
    }

    while (v < detent) {
      __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
      __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
      x = _mm_aesdec_si128(x, v0y);
      y = _mm_aesdec_si128(y, v1x);
    }

    x = _mm_add_epi64(_mm_aesdec_si128(x, _mm_aesenc_si128(y, x)), y);
#if defined(__x86_64__) || defined(_M_X64)
    a = _mm_cvtsi128_si64(x);
#if defined(__SSE4_1__)
    b = _mm_extract_epi64(x, 1);
#else
    b = _mm_cvtsi128_si64(_mm_unpackhi_epi64(x, x));
#endif
#else
    a = (uint32_t)_mm_cvtsi128_si32(x);
#if defined(__SSE4_1__)
    a |= (uint64_t)_mm_extract_epi32(x, 1) << 32;
    b = (uint32_t)_mm_extract_epi32(x, 2) |
        (uint64_t)_mm_extract_epi32(x, 3) << 32;
#else
    a |= (uint64_t)_mm_cvtsi128_si32(_mm_shuffle_epi32(x, 1)) << 32;
    x = _mm_unpackhi_epi64(x, x);
    b = (uint32_t)_mm_cvtsi128_si32(x);
    b |= (uint64_t)_mm_cvtsi128_si32(_mm_shuffle_epi32(x, 1)) << 32;
#endif
#endif
  }

  const uint64_t *v = (const uint64_t *)data;
  switch (len) {
  default:
    b += mux64(*v++, p4);
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    a += mux64(*v++, p3);
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    b += mux64(*v++, p2);
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    a += mux64(tail64_le(v, len), p1);
  case 0:
    return mux64(rot64(a + b, s1), p4) + mix64(a ^ b, p0);
  }
}

static uint64_t
#if __GNUC_PREREQ(4, 4) || __has_attribute(target)
    __attribute__((target("aes,no-avx,no-avx2")))
#endif
    t1ha_ia32aes_noavx(const void *data, size_t len, uint64_t seed) {

#else /* ELF && ifunc */

T1HA_INTERNAL uint64_t
#if __GNUC_PREREQ(4, 4) || __has_attribute(target)
    __attribute__((target("aes")))
#endif
    _t1ha_ia32aes(const void *data, size_t len, uint64_t seed) {
#endif
  uint64_t a = seed;
  uint64_t b = len;

  if (unlikely(len > 32)) {
    __m128i x = _mm_set_epi64x(a, b);
    __m128i y = _mm_aesenc_si128(x, _mm_set_epi64x(p0, p1));

    const __m128i *v = (const __m128i *)data;
    const __m128i *const detent =
        (const __m128i *)((const uint8_t *)data + (len & ~15ul));
    data = detent;

    if (len & 16) {
      x = _mm_add_epi64(x, _mm_loadu_si128(v++));
      y = _mm_aesenc_si128(x, y);
    }
    len &= 15;

    if (v + 7 < detent) {
      __m128i salt = y;
      do {
        __m128i t = _mm_aesenc_si128(_mm_loadu_si128(v++), salt);
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));

        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));
        t = _mm_aesdec_si128(t, _mm_loadu_si128(v++));

        salt = _mm_add_epi64(salt, _mm_set_epi64x(p2, p3));
        t = _mm_aesenc_si128(x, t);
        x = _mm_add_epi64(y, x);
        y = t;
      } while (v + 7 < detent);
    }

    while (v < detent) {
      __m128i v0y = _mm_add_epi64(y, _mm_loadu_si128(v++));
      __m128i v1x = _mm_sub_epi64(x, _mm_loadu_si128(v++));
      x = _mm_aesdec_si128(x, v0y);
      y = _mm_aesdec_si128(y, v1x);
    }

    x = _mm_add_epi64(_mm_aesdec_si128(x, _mm_aesenc_si128(y, x)), y);
#if defined(__x86_64__) || defined(_M_X64)
    a = _mm_cvtsi128_si64(x);
#if defined(__SSE4_1__)
    b = _mm_extract_epi64(x, 1);
#else
    b = _mm_cvtsi128_si64(_mm_unpackhi_epi64(x, x));
#endif
#else
    a = (uint32_t)_mm_cvtsi128_si32(x);
#if defined(__SSE4_1__)
    a |= (uint64_t)_mm_extract_epi32(x, 1) << 32;
    b = (uint32_t)_mm_extract_epi32(x, 2) |
        (uint64_t)_mm_extract_epi32(x, 3) << 32;
#else
    a |= (uint64_t)_mm_cvtsi128_si32(_mm_shuffle_epi32(x, 1)) << 32;
    x = _mm_unpackhi_epi64(x, x);
    b = (uint32_t)_mm_cvtsi128_si32(x);
    b |= (uint64_t)_mm_cvtsi128_si32(_mm_shuffle_epi32(x, 1)) << 32;
#endif
#endif
  }

  const uint64_t *v = (const uint64_t *)data;
  switch (len) {
  default:
    b += mux64(*v++, p4);
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    a += mux64(*v++, p3);
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    b += mux64(*v++, p2);
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    a += mux64(tail64_le(v, len), p1);
  case 0:
    return mux64(rot64(a + b, s1), p4) + mix64(a ^ b, p0);
  }
}

#endif /* __i386__ || __x86_64__ */

/***************************************************************************/

static
#if __GNUC_PREREQ(4, 0) || __has_attribute(used)
    __attribute__((used))
#endif
    uint64_t (*t1ha0_resolve(void))(const void *, size_t, uint64_t) {
#ifdef T1HA_ia32aes_AVAILABLE

  uint32_t features = x86_cpu_features();
  if (features & (1l << 25))
    return _t1ha_ia32aes;
#endif /* T1HA_ia32aes_AVAILABLE */

  return (sizeof(size_t) >= 8)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
             ? t1ha1_be
             : _t1ha_32be;
#else
             ? t1ha1_le
             : _t1ha_32le;
#endif
}

#ifdef __ELF__

#if __GNUC_PREREQ(4, 6) || __has_attribute(ifunc)
uint64_t t1ha0(const void *data, size_t len, uint64_t seed)
    __attribute__((ifunc("t1ha0_resolve")));
#else
__asm("\t.globl\tt1ha0\n\t.type\tt1ha0, "
      "@gnu_indirect_function\n\t.set\tt1ha0,t1ha0_resolve");
#endif /* ifunc */

#elif __GNUC_PREREQ(4, 0) || __has_attribute(constructor)

uint64_t (*_t1ha0_ptr)(const void *, size_t, uint64_t);

static void __attribute__((constructor)) t1ha0_init(void) {
  _t1ha0_ptr = t1ha0_resolve();
}

#else /* ELF */

static uint64_t t1ha0_proxy(const void *data, size_t len, uint64_t seed) {
  _t1ha0_ptr = t1ha0_resolve();
  return _t1ha0_ptr(data, len, seed);
}

uint64_t (*_t1ha0_ptr)(const void *, size_t, uint64_t) = t1ha0_proxy;

#endif
