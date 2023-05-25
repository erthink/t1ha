/*
 *  Copyright (c) 2020 Leonid Yuriev <leo@yuriev.ru>,
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
#include "wyhash.h"

uint64_t thunk_wyhash_20221102(const void *input, size_t length,
                               uint64_t seed) {
  return wyhash(input, length, seed, _wyp);
}

bool wyhash_20221102_selftest(void) {
  bool failed = wyhash(NULL, 0, 0, _wyp) != UINT64_C(0x42bc986dc5eec4d3);
  failed |= wyhash("a", 1, 1, _wyp) != UINT64_C(0x84508dc903c31551);
  failed |= wyhash("abc", 3, 2, _wyp) != UINT64_C(0xbc54887cfc9ecb1);
  failed |=
      wyhash("message digest", 14, 3, _wyp) != UINT64_C(0xadc146444841c430);
  failed |= wyhash("abcdefghijklmnopqrstuvwxyz", 26, 4, _wyp) !=
            UINT64_C(0x4c0977bd4f14f34a);
  failed |=
      wyhash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
             62, 5, _wyp) != UINT64_C(0x6f8bd609a8a276d2);
  failed |= wyhash("12345678901234567890123456789012345678901234567890123456789"
                   "012345678901234567890",
                   80, 6, _wyp) != UINT64_C(0x498d7c21668259ad);
  return failed;
}

const uint64_t refval_wyhash_20221102[81] = {
    UINT64_C(0x0409638EE2BDE459), UINT64_C(0x20AC8B93D401D5E6),
    UINT64_C(0xADF5D942B29AC953), UINT64_C(0x85669AF5073EE8BE),
    UINT64_C(0xA3D943AE2A6A1F49), UINT64_C(0xACEB1673F381D842),
    UINT64_C(0xB8F865B9B67D71F1), UINT64_C(0xA823CA869C757D01),
    UINT64_C(0x515DEA81A624910F), UINT64_C(0x16512C92EF02820E),
    UINT64_C(0xD092B9938C07AFE9), UINT64_C(0x7B2D35E96C8BA7A7),
    UINT64_C(0x6D0B8FC30333766E), UINT64_C(0x779F3BCB4537DCB3),
    UINT64_C(0xCFE564C0AA14F310), UINT64_C(0x77D3AABECC41447F),
    UINT64_C(0xCDE8A6F00447CBEF), UINT64_C(0x443AB500177172F3),
    UINT64_C(0x52F9295860FF7508), UINT64_C(0x0814B2D8D1F8BA2F),
    UINT64_C(0x6392C84FE42811BA), UINT64_C(0x9BB4ADAFA9D22B3C),
    UINT64_C(0x54EA1BB3B85CC6F6), UINT64_C(0xD8D35AA18FF9437D),
    UINT64_C(0xD651F4DFED91193D), UINT64_C(0x66D61A1812CF88CB),
    UINT64_C(0xC56BBE49BB86C144), UINT64_C(0xB923E2245EF3992C),
    UINT64_C(0x178F823861148013), UINT64_C(0x28508E8C2668A35B),
    UINT64_C(0x3300E573BAAF799C), UINT64_C(0x3A927FD33A784518),
    UINT64_C(0xA7BD74219F20C3C0), UINT64_C(0xDA8673005B55D0EC),
    UINT64_C(0x59385BF4E094F4C0), UINT64_C(0x5465707439543CAD),
    UINT64_C(0xD5D5B909A7F48AE0), UINT64_C(0xACE58AC11CD3A86C),
    UINT64_C(0x641B2163F08F27CE), UINT64_C(0x157A09D318CEB3D5),
    UINT64_C(0xBE00A4D76D45DD9D), UINT64_C(0x060C9893E6DD73FE),
    UINT64_C(0xA3636A34F128CFDC), UINT64_C(0xEF1877BF3A115E1E),
    UINT64_C(0x9E8A8E936360BB86), UINT64_C(0x4E6D68F0D3DE72C0),
    UINT64_C(0xB259F961BCADAC3F), UINT64_C(0x30F920AC087D79C3),
    UINT64_C(0x061299C04CEC0497), UINT64_C(0x60A506EB14A66CD3),
    UINT64_C(0x9CFF515DFCDCC27B), UINT64_C(0x9AA94CF1E091A90E),
    UINT64_C(0x4A7EF439DD279283), UINT64_C(0xAFF445AFECDF6747),
    UINT64_C(0x5DB3CCA6D4A94743), UINT64_C(0x70C94AB02256340F),
    UINT64_C(0x00F872F67F7B0984), UINT64_C(0xFA1936C9F46C2DDB),
    UINT64_C(0x0FB69B5CDCC4E06C), UINT64_C(0x632F83BA82DB982D),
    UINT64_C(0x85E11D763BD37EB1), UINT64_C(0x85E91AC3CF02E2E4),
    UINT64_C(0x91FBBF5B85956695), UINT64_C(0xF2139573275574A0),
    UINT64_C(0x0F783945C534D10A), UINT64_C(0x39DA7FACA6F862EE),
    UINT64_C(0x08F4AA2C7C360739), UINT64_C(0xBB39EB5E18C7BEC6),
    UINT64_C(0x00B1A7C3D3C462AA), UINT64_C(0x7D427996B8FEA79F),
    UINT64_C(0x6EF01EB123B957C7), UINT64_C(0xC5E3F5A764689B23),
    UINT64_C(0x77EFD58244C30D34), UINT64_C(0xCB1A99B226F4335B),
    UINT64_C(0x2A747A3A2645497C), UINT64_C(0xDFAA75DA597CDC98),
    UINT64_C(0x6CF8D4DDD4B6712D), UINT64_C(0x2AAB2280F8059908),
    UINT64_C(0xFDFDEFA760BB4480), UINT64_C(0x0D8AE62BBF275DBD),
    UINT64_C(0x7FA21E9E6D9EED92)};
