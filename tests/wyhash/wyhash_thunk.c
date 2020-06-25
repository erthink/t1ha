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

uint64_t thunk_wyhash_v7(const void *input, size_t length, uint64_t seed) {
  return wyhash(input, length, seed, _wyp);
}

bool wyhash_v7_selftest(void) {
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

const uint64_t refval_wyhash_v7[81] = {
    UINT64_C(0x42BC986DC5EEC4D3), UINT64_C(0x33214C455B46F3A5),
    UINT64_C(0x3C7EB0CF25FEC53D), UINT64_C(0xA2779E9AE8667368),
    UINT64_C(0x244CE25B34F1A7C6), UINT64_C(0x81FC2C02C9159AEF),
    UINT64_C(0xED465549F80AFF68), UINT64_C(0xC52A4A2569FCC2A3),
    UINT64_C(0x7A471FD1AAA5CAEE), UINT64_C(0xBED4FC242BBB84E1),
    UINT64_C(0x002AFF6CAAD72D9A), UINT64_C(0xD962259BC2219CFF),
    UINT64_C(0x98DC859A4E52A5C2), UINT64_C(0xCD515E5A118BFF8E),
    UINT64_C(0x9D708B21CAFACCBF), UINT64_C(0xB4D397722D29DD8E),
    UINT64_C(0x9AF656FE3443DC8E), UINT64_C(0x0199C2857DC8F252),
    UINT64_C(0x6C150A9FAF322194), UINT64_C(0xC82481A302B04512),
    UINT64_C(0x230B94D429EDD7BB), UINT64_C(0xEFA3BF0492518AD2),
    UINT64_C(0xF1B2E7C9F209A3DD), UINT64_C(0x981FC23CA49C06CF),
    UINT64_C(0x69E3DDFAA85DDF2F), UINT64_C(0x508698BE0F001518),
    UINT64_C(0xF5414CF0165E784F), UINT64_C(0x65F341C899C801A4),
    UINT64_C(0x4C1BA4FD609A6777), UINT64_C(0x4462F42A3DBE6D33),
    UINT64_C(0x27E63A5A9B69E2B8), UINT64_C(0x70DB381691D2A561),
    UINT64_C(0xD99220B021D287D1), UINT64_C(0xF254F5D6FD5AA0F4),
    UINT64_C(0x1FF6F1471AA31B3E), UINT64_C(0x42F6DA7B74EF1BBF),
    UINT64_C(0x5FF9431F03D6906F), UINT64_C(0x063BAD519C4F6A03),
    UINT64_C(0x0173194D209D7336), UINT64_C(0xF9ED153AD46D3A44),
    UINT64_C(0x25573414AE3BEBD2), UINT64_C(0x243654CC1C5C0367),
    UINT64_C(0x2D9AF60E71488D7C), UINT64_C(0x699B05D6D432AE35),
    UINT64_C(0xF5A0C3CD8B99DF54), UINT64_C(0xC2EDB15A89F92E02),
    UINT64_C(0x8D6410BD03DD7655), UINT64_C(0x32DE061DC7AAC972),
    UINT64_C(0x0DE1382B1214819E), UINT64_C(0xE83FA2412C855143),
    UINT64_C(0x9E418E279447CBB3), UINT64_C(0x05D7B28BF50C4F63),
    UINT64_C(0x6612ABD6DAB0AEB6), UINT64_C(0x7B46C1C71BC8A2A1),
    UINT64_C(0xD5D7512D9930A94C), UINT64_C(0x8F18E79AE0F2D28C),
    UINT64_C(0x02E5C3119946E6ED), UINT64_C(0x72F0917B51092A95),
    UINT64_C(0xFEB2C655C83DD8BA), UINT64_C(0x48D81C24400CDBF4),
    UINT64_C(0x3E6E56A277EC1DC0), UINT64_C(0x0C233D62FD26F9F8),
    UINT64_C(0x824F4FCF50D91D09), UINT64_C(0xA28E9E9D503A1E14),
    UINT64_C(0xDE7DB070EBBC8FD4), UINT64_C(0x960B26F979722378),
    UINT64_C(0x86AAC9D7AC6CFD9B), UINT64_C(0x1F58008965BEC64D),
    UINT64_C(0x60021E853B676D22), UINT64_C(0x7549581D400EB04B),
    UINT64_C(0x34790F730EAF1944), UINT64_C(0xAB04E4787C19F219),
    UINT64_C(0xA177C45D95E2C2E6), UINT64_C(0xF0B5687A932DD21E),
    UINT64_C(0x711F571234EC4E6F), UINT64_C(0x5A9D344D5E7D3F0E),
    UINT64_C(0x47882BD10383685B), UINT64_C(0x86A9CB99A3FF7EAB),
    UINT64_C(0x549C4C769EA34A69), UINT64_C(0x1165CC1F165932BB),
    UINT64_C(0x01E29D669AC4796D)};
