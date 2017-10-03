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

#if defined(_MSC_VER) && _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif

#include "../t1ha.h"
#include "t1ha_bits.h"

uint64_t t1ha1_le(const void *data, size_t len, uint64_t seed) {
  uint64_t a = seed;
  uint64_t b = len;

  const int need_align = (((uintptr_t)data) & 7) != 0 && !UNALIGNED_OK;
  uint64_t align[4];

  if (unlikely(len > 32)) {
    uint64_t c = rot64(len, s1) + seed;
    uint64_t d = len ^ rot64(seed, s1);
    const void *detent = (const uint8_t *)data + len - 31;
    do {
      const uint64_t *v = (const uint64_t *)data;
      if (unlikely(need_align))
        v = (const uint64_t *)memcpy(&align, v, 32);

      uint64_t w0 = fetch64_le(v + 0);
      uint64_t w1 = fetch64_le(v + 1);
      uint64_t w2 = fetch64_le(v + 2);
      uint64_t w3 = fetch64_le(v + 3);

      uint64_t d02 = w0 ^ rot64(w2 + d, s1);
      uint64_t c13 = w1 ^ rot64(w3 + c, s1);
      c += a ^ rot64(w0, s0);
      d -= b ^ rot64(w1, s2);
      a ^= p1 * (d02 + w3);
      b ^= p0 * (c13 + w2);
      data = (const uint64_t *)data + 4;
    } while (likely(data < detent));

    a ^= p6 * (rot64(c, s1) + d);
    b ^= p5 * (c + rot64(d, s1));
    len &= 31;
  }

  const uint64_t *v = (const uint64_t *)data;
  if (unlikely(need_align) && len > 8)
    v = (const uint64_t *)memcpy(&align, v, len);

  switch (len) {
  default:
    b += mux64(fetch64_le(v++), p4);
  /* fall through */
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    a += mux64(fetch64_le(v++), p3);
  /* fall through */
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    b += mux64(fetch64_le(v++), p2);
  /* fall through */
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    a += mux64(tail64_le(v, len), p1);
  /* fall through */
  case 0:
    return mux64(rot64(a + b, s1), p4) + mix64(a ^ b, p0);
  }
}

uint64_t t1ha1_be(const void *data, size_t len, uint64_t seed) {
  uint64_t a = seed;
  uint64_t b = len;

  const int need_align = (((uintptr_t)data) & 7) != 0 && !UNALIGNED_OK;
  uint64_t align[4];

  if (unlikely(len > 32)) {
    uint64_t c = rot64(len, s1) + seed;
    uint64_t d = len ^ rot64(seed, s1);
    const void *detent = (const uint8_t *)data + len - 31;
    do {
      const uint64_t *v = (const uint64_t *)data;
      if (unlikely(need_align))
        v = (const uint64_t *)memcpy(&align, v, 32);

      uint64_t w0 = fetch64_be(v + 0);
      uint64_t w1 = fetch64_be(v + 1);
      uint64_t w2 = fetch64_be(v + 2);
      uint64_t w3 = fetch64_be(v + 3);

      uint64_t d02 = w0 ^ rot64(w2 + d, s1);
      uint64_t c13 = w1 ^ rot64(w3 + c, s1);
      c += a ^ rot64(w0, s0);
      d -= b ^ rot64(w1, s2);
      a ^= p1 * (d02 + w3);
      b ^= p0 * (c13 + w2);
      data = (const uint64_t *)data + 4;
    } while (likely(data < detent));

    a ^= p6 * (rot64(c, s1) + d);
    b ^= p5 * (c + rot64(d, s1));
    len &= 31;
  }

  const uint64_t *v = (const uint64_t *)data;
  if (unlikely(need_align) && len > 8)
    v = (const uint64_t *)memcpy(&align, v, len);

  switch (len) {
  default:
    b += mux64(fetch64_be(v++), p4);
  /* fall through */
  case 24:
  case 23:
  case 22:
  case 21:
  case 20:
  case 19:
  case 18:
  case 17:
    a += mux64(fetch64_be(v++), p3);
  /* fall through */
  case 16:
  case 15:
  case 14:
  case 13:
  case 12:
  case 11:
  case 10:
  case 9:
    b += mux64(fetch64_be(v++), p2);
  /* fall through */
  case 8:
  case 7:
  case 6:
  case 5:
  case 4:
  case 3:
  case 2:
  case 1:
    a += mux64(tail64_be(v, len), p1);
  /* fall through */
  case 0:
    return mux64(rot64(a + b, s1), p4) + mix64(a ^ b, p0);
  }
}
