/* StadtX hash implementaion.
 * Author: Yves Orton <demerphq@gmail.com>.
 * License: LGPLv3.
 *
 * This file copied from https://github.com/demerphq/BeagleHash
 * Please refer there for detailed Copyright and License information. */
#ifndef STADTX_HASH_H
#define STADTX_HASH_H

/* LY: simple way to fix endianess and provide portable marcos */
#include "../../src/t1ha_bits.h"
#define ROTL64(x, r) rot64(x, 64 - r)
#define ROTR64(x, r) rot64(x, r)

/* do a marsaglia xor-shift permutation followed by a
 * multiply by a prime (presumably large) and another
 * marsaglia xor-shift permutation.
 * One of these thoroughly changes the bits of the input.
 * Two of these with different primes passes the Strict Avalanche Criteria
 * in all the tests I did.
 *
 * Note that v cannot end up zero after a scramble64 unless it
 * was zero in the first place.
 */
#define STADTX_SCRAMBLE64(v, prime)                                            \
  do {                                                                         \
    v ^= (v >> 13);                                                            \
    v ^= (v << 35);                                                            \
    v ^= (v >> 30);                                                            \
    v *= prime;                                                                \
    v ^= (v >> 19);                                                            \
    v ^= (v << 15);                                                            \
    v ^= (v >> 46);                                                            \
  } while (0)

static __inline void stadtx_seed_state(const uint64_t *seed, uint64_t *state) {
  /* first we apply two masks to each word of the seed, this means that
   * a) at least one of state[0] and state[2] is nonzero,
   * b) at least one of state[1] and state[3] is nonzero
   * c) that state[0] and state[2] are different
   * d) that state[1] and state[3] are different
   * e) that the replacement value for any zero's is a totally different from
   * the seed value. (iow, if seed[0] is 0x43f6a8885a308d31UL then state[0]
   * becomes 0, which is the replaced with 1, which is totally different.). */
  /* hex expansion of pi, skipping first two digits. pi= 3.2[43f6...]*/
  /* pi value in hex from here:
   * http://turner.faculty.swau.edu/mathematics/materialslibrary/pi/pibases.html*/
  state[0] = seed[0] ^ 0x43f6a8885a308d31UL;
  state[1] = seed[1] ^ 0x3198a2e03707344aUL;
  state[2] = seed[0] ^ 0x4093822299f31d00UL;
  state[3] = seed[1] ^ 0x82efa98ec4e6c894UL;
  if (!state[0])
    state[0] = 1;
  if (!state[1])
    state[1] = 2;
  if (!state[2])
    state[2] = 4;
  if (!state[3])
    state[3] = 8;
  /* and now for good measure we double scramble all four -
   * a double scramble guarantees a complete avalanche of all the
   * bits in the seed - IOW, by the time we are hashing the
   * four state vectors should be completely different and utterly
   * uncognizable from the input seed bits */
  STADTX_SCRAMBLE64(state[0], 0x801178846e899d17UL);
  STADTX_SCRAMBLE64(state[0], 0xdd51e5d1c9a5a151UL);
  STADTX_SCRAMBLE64(state[1], 0x93a7d6c8c62e4835UL);
  STADTX_SCRAMBLE64(state[1], 0x803340f36895c2b5UL);
  STADTX_SCRAMBLE64(state[2], 0xbea9344eb7565eebUL);
  STADTX_SCRAMBLE64(state[2], 0xcd95d1e509b995cdUL);
  STADTX_SCRAMBLE64(state[3], 0x9999791977e30c13UL);
  STADTX_SCRAMBLE64(state[3], 0xaab8b6b05abfc6cdUL);
}

#define STADTX_K0_uint64_t 0xb89b0f8e1655514fUL
#define STADTX_K1_uint64_t 0x8c6f736011bd5127UL
#define STADTX_K2_uint64_t 0x8f29bd94edce7b39UL
#define STADTX_K3_uint64_t 0x9c1b8e1e9628323fUL

#define STADTX_K2_uint32_t 0x802910e3
#define STADTX_K3_uint32_t 0x819b13af
#define STADTX_K4_uint32_t 0x91cb27e5
#define STADTX_K5_uint32_t 0xc1a269c1

static __inline uint64_t stadtx_hash_with_state(const uint64_t *state_ch,
                                                const uint8_t *key,
                                                const size_t key_len) {
  uint64_t *state = (uint64_t *)state_ch;
  uint64_t len = key_len;
  uint64_t v0 = state[0] ^ ((key_len + 1) * STADTX_K0_uint64_t);
  uint64_t v1 = state[1] ^ ((key_len + 2) * STADTX_K1_uint64_t);
  if (len < 32) {
    switch (len >> 3) {
    case 3:
      v0 += fetch64_le_unaligned(key) * STADTX_K3_uint64_t;
      v0 = ROTR64(v0, 17) ^ v1;
      v1 = ROTR64(v1, 53) + v0;
      key += 8;
      /* fallthrough */
    case 2:
      v0 += fetch64_le_unaligned(key) * STADTX_K3_uint64_t;
      v0 = ROTR64(v0, 17) ^ v1;
      v1 = ROTR64(v1, 53) + v0;
      key += 8;
      /* fallthrough */
    case 1:
      v0 += fetch64_le_unaligned(key) * STADTX_K3_uint64_t;
      v0 = ROTR64(v0, 17) ^ v1;
      v1 = ROTR64(v1, 53) + v0;
      key += 8;
      /* fallthrough */
    case 0:
    default:
      break;
    }
    switch (len & 0x7) {
    case 7:
      v0 += (uint64_t)key[6] << 32;
      /* fallthrough */
    case 6:
      v1 += (uint64_t)key[5] << 48;
      /* fallthrough */
    case 5:
      v0 += (uint64_t)key[4] << 16;
      /* fallthrough */
    case 4:
      v1 += (uint64_t)fetch32_le_unaligned(key);
      break;
    case 3:
      v0 += (uint64_t)key[2] << 48;
      /* fallthrough */
    case 2:
      v1 += (uint64_t)fetch16_le_unaligned(key);
      break;
    case 1:
      v0 += (uint64_t)key[0];
      /* fallthrough */
    case 0:
      v1 = ROTL64(v1, 32) ^ 0xFF;
      break;
    }
    v1 ^= v0;
    v0 = ROTR64(v0, 33) + v1;
    v1 = ROTL64(v1, 17) ^ v0;
    v0 = ROTL64(v0, 43) + v1;
    v1 = ROTL64(v1, 31) - v0;
    v0 = ROTL64(v0, 13) ^ v1;
    v1 -= v0;
    v0 = ROTL64(v0, 41) + v1;
    v1 = ROTL64(v1, 37) ^ v0;
    v0 = ROTR64(v0, 39) + v1;
    v1 = ROTR64(v1, 15) + v0;
    v0 = ROTL64(v0, 15) ^ v1;
    v1 = ROTR64(v1, 5);
    return v0 ^ v1;
  } else {
    uint64_t v2 = state[2] ^ ((key_len + 3) * STADTX_K2_uint64_t);
    uint64_t v3 = state[3] ^ ((key_len + 4) * STADTX_K3_uint64_t);

    do {
      v0 += (uint64_t)fetch64_le_unaligned(key + 0) * STADTX_K2_uint32_t;
      v0 = ROTL64(v0, 57) ^ v3;
      v1 += (uint64_t)fetch64_le_unaligned(key + 8) * STADTX_K3_uint32_t;
      v1 = ROTL64(v1, 63) ^ v2;
      v2 += (uint64_t)fetch64_le_unaligned(key + 16) * STADTX_K4_uint32_t;
      v2 = ROTR64(v2, 47) + v0;
      v3 += (uint64_t)fetch64_le_unaligned(key + 24) * STADTX_K5_uint32_t;
      v3 = ROTR64(v3, 11) - v1;
      key += 32;
      len -= 32;
    } while (len >= 32);

    switch (len >> 3) {
    case 3:
      v0 += ((uint64_t)fetch64_le_unaligned(key) * STADTX_K2_uint32_t);
      key += 8;
      v0 = ROTL64(v0, 57) ^ v3;
      /* fallthrough */
    case 2:
      v1 += ((uint64_t)fetch64_le_unaligned(key) * STADTX_K3_uint32_t);
      key += 8;
      v1 = ROTL64(v1, 63) ^ v2;
      /* fallthrough */
    case 1:
      v2 += ((uint64_t)fetch64_le_unaligned(key) * STADTX_K4_uint32_t);
      key += 8;
      v2 = ROTR64(v2, 47) + v0;
      /* fallthrough */
    case 0:
      v3 = ROTR64(v3, 11) - v1;
    }
    v0 ^= (len + 1) * STADTX_K3_uint64_t;
    switch (len & 0x7) {
    case 7:
      v1 += (uint64_t)key[6];
      /* fallthrough */
    case 6:
      v2 += (uint64_t)fetch16_le_unaligned(key + 4);
      v3 += (uint64_t)fetch32_le_unaligned(key);
      break;
    case 5:
      v1 += (uint64_t)key[4];
      /* fallthrough */
    case 4:
      v2 += (uint64_t)fetch32_le_unaligned(key);
      break;
    case 3:
      v3 += (uint64_t)key[2];
      /* fallthrough */
    case 2:
      v1 += (uint64_t)fetch16_le_unaligned(key);
      break;
    case 1:
      v2 += (uint64_t)key[0];
      /* fallthrough */
    case 0:
      v3 = ROTL64(v3, 32) ^ 0xFF;
      break;
    }

    v1 -= v2;
    v0 = ROTR64(v0, 19);
    v1 -= v0;
    v1 = ROTR64(v1, 53);
    v3 ^= v1;
    v0 -= v3;
    v3 = ROTL64(v3, 43);
    v0 += v3;
    v0 = ROTR64(v0, 3);
    v3 -= v0;
    v2 = ROTR64(v2, 43) - v3;
    v2 = ROTL64(v2, 55) ^ v0;
    v1 -= v2;
    v3 = ROTR64(v3, 7) - v2;
    v2 = ROTR64(v2, 31);
    v3 += v2;
    v2 -= v1;
    v3 = ROTR64(v3, 39);
    v2 ^= v3;
    v3 = ROTR64(v3, 17) ^ v2;
    v1 += v3;
    v1 = ROTR64(v1, 9);
    v2 ^= v1;
    v2 = ROTL64(v2, 24);
    v3 ^= v2;
    v3 = ROTR64(v3, 59);
    v0 = ROTR64(v0, 1) - v1;

    return v0 ^ v1 ^ v2 ^ v3;
  }
}

static __inline uint64_t stadtx_hash(const uint64_t *seed_ch, const void *key,
                                     const size_t key_len) {
  uint64_t state[4];
  stadtx_seed_state(seed_ch, state);
  return stadtx_hash_with_state(state, key, key_len);
}

#endif
