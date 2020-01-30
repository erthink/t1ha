/*
 *  Copyright (c) 2016-2020 Leonid Yuriev <leo@yuriev.ru>,
 *  Fast Positive Hash.
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

#include "../common.h"

#define XXH_STATIC_LINKING_ONLY
#define XXH_INLINE_ALL
#define XXH_PRIVATE_API
#define XXH_VECTOR 0

#include "xxhash.h"

uint64_t XXH_32(const void *input, size_t length, uint64_t seed) {
  return XXH32(input, length, (uint32_t)seed);
}

uint64_t XXH_64(const void *input, size_t length, uint64_t seed) {
  return XXH64(input, length, seed);
}

/* xxHash3 */
uint64_t XXH3_64(const void *input, size_t length, uint64_t seed) {
  return XXH3_64bits_withSeed(input, length, seed);
}

uint64_t XXH3_128(const void *input, size_t length, uint64_t seed) {
  return XXH3_128bits_withSeed(input, length, seed).low64;
}
