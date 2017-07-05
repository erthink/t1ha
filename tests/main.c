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

#include "../t1ha.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#pragma warning(disable : 4711) /* function 'xyz' selected for                 \
                                   automatic inline expansion */
#pragma warning(disable : 4127) /* conditional expression is constant */
#if _MSC_VER < 1900
#define snprintf _snprintf
#pragma warning(disable : 4996) /* '_snprintf': This function or variable      \
                                   may be unsafe */
#endif
#endif /* MSVC */

/* *INDENT-OFF* */
/* clang-format off */
static const uint8_t pattern[64] = {
  0, 1, 2, 3, 4, 5, 6, 7, 0xFF, 0x7F, 0x3F, 0x1F, 0xF, 8, 16, 32, 64, 0x80, 0xFE,
  0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x55, 0xAA,
  11, 17, 19, 23, 29, 37, 42, 43, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
  'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x'
};
/* *INDENT-ON* */
/* clang-format on */

int verbose;

int probe(uint64_t (*hash)(const void *, size_t, uint64_t), const char *caption,
          const uint64_t check, const void *data, unsigned len, uint64_t seed) {
  uint64_t value = hash(data, len, seed);
  if (verbose || value != check)
    printf("Pattern '%s', reference value %08X%08X: ", caption,
           (uint32_t)(check >> 32), (uint32_t)check);
  if (check == value) {
    if (verbose)
      printf("Passed\n");
    return 0;
  }
  printf("Failed! Got %08X%08X\n", (uint32_t)(value >> 32), (uint32_t)value);
  return -1;
}

int test(const char *title, uint64_t (*hash)(const void *, size_t, uint64_t),
         const uint64_t *reference_values) {
  printf("Testing %s...%s", title, verbose ? "\n" : "");

  const uint64_t zero = 0;
  int failed = 0;
  failed |= probe(hash, "empty-zero", 0, NULL, 0, zero);
  failed |= probe(hash, "empty-all1", *reference_values++, NULL, 0, ~zero);
  failed |= probe(hash, "bin64-zero", *reference_values++, pattern, 64, zero);

  char caption[32];
  uint64_t seed = 1;
  for (int i = 1; i < 64; i++) {
    snprintf(caption, sizeof(caption), "bin%02i-1p%02u", i, i & 63);
    failed |= probe(hash, caption, *reference_values++, pattern, i, seed);
    seed <<= 1;
  }

  seed = ~zero;
  for (int i = 1; i <= 7; i++) {
    seed <<= 1;
    snprintf(caption, sizeof(caption), "align%i_F%u", i, 64 - i);
    failed |=
        probe(hash, caption, *reference_values++, pattern + i, 64 - i, seed);
  }

  uint8_t pattern_long[512];
  for (size_t i = 0; i < sizeof(pattern_long); ++i)
    pattern_long[i] = (uint8_t)i;
  for (int i = 0; i <= 7; i++) {
    snprintf(caption, sizeof(caption), "long-%05u", 128 + i * 17);
    failed |= probe(hash, caption, *reference_values++, pattern_long + i,
                    128 + i * 17, seed);
  }

  printf(" %s\n", (!verbose && !failed) ? "Ok" : "");
  return failed;
}

/* *INDENT-OFF* */
/* clang-format off */
static const uint64_t refval_64le[80] = {
  0x6A580668D6048674, 0xA2FE904AFF0D0879, 0xE3AB9C06FAF4D023, 0x6AF1C60874C95442,
  0xB3557E561A6C5D82, 0x0AE73C696F3D37C0, 0x5EF25F7062324941, 0x9B784F3B4CE6AF33,
  0x6993BB206A74F070, 0xF1E95DF109076C4C, 0x4E1EB70C58E48540, 0x5FDD7649D8EC44E4,
  0x559122C706343421, 0x380133D58665E93D, 0x9CE74296C8C55AE4, 0x3556F9A5757AB6D0,
  0xF62751F7F25C469E, 0x851EEC67F6516D94, 0xED463EE3848A8695, 0xDC8791FEFF8ED3AC,
  0x2569C744E1A282CF, 0xF90EB7C1D70A80B9, 0x68DFA6A1B8050A4C, 0x94CCA5E8210D2134,
  0xF5CC0BEABC259F52, 0x40DBC1F51618FDA7, 0x0807945BF0FB52C6, 0xE5EF7E09DE70848D,
  0x63E1DF35FEBE994A, 0x2025E73769720D5A, 0xAD6120B2B8A152E1, 0x2A71D9F13959F2B7,
  0x8A20849A27C32548, 0x0BCBC9FE3B57884E, 0x0E028D255667AEAD, 0xBE66DAD3043AB694,
  0xB00E4C1238F9E2D4, 0x5C54BDE5AE280E82, 0x0E22B86754BC3BC4, 0x016707EBF858B84D,
  0x990015FBC9E095EE, 0x8B9AF0A3E71F042F, 0x6AA56E88BD380564, 0xAACE57113E681A0F,
  0x19F81514AFA9A22D, 0x80DABA3D62BEAC79, 0x715210412CABBF46, 0xD8FA0B9E9D6AA93F,
  0x6C2FC5A4109FD3A2, 0x5B3E60EEB51DDCD8, 0x0A7C717017756FE7, 0xA73773805CA31934,
  0x4DBD6BB7A31E85FD, 0x24F619D3D5BC2DB4, 0x3E4AF35A1678D636, 0x84A1A8DF8D609239,
  0x359C862CD3BE4FCD, 0xCF3A39F5C27DC125, 0xC0FF62F8FD5F4C77, 0x5E9F2493DDAA166C,
  0x17424152BE1CA266, 0xA78AFA5AB4BBE0CD, 0x7BFB2E2CEF118346, 0x647C3E0FF3E3D241,
  0x0352E4055C13242E, 0x6F42FC70EB660E38, 0x0BEBAD4FABF523BA, 0x9269F4214414D61D,
  0x1CA8760277E6006C, 0x7BAD25A859D87B5D, 0xAD645ADCF7414F1D, 0xB07F517E88D7AFB3,
  0xB321C06FB5FFAB5C, 0xD50F162A1EFDD844, 0x1DFD3D1924FBE319, 0xDFAEAB2F09EF7E78,
  0xA7603B5AF07A0B1E, 0x41CD044C0E5A4EE3, 0xF64D2F86E813BF33, 0xFF9FDB99305EB06A
};

static const uint64_t refval_64be[80] = {
  0x6A580668D6048674, 0xDECC975A0E3B8177, 0xE3AB9C06FAF4D023, 0xE401FA8F1B6AF969,
  0x67DB1DAE56FB94E3, 0x1106266A09B7A073, 0x550339B1EF2C7BBB, 0x290A2BAF590045BB,
  0xA182C1258C09F54A, 0x137D53C34BE7143A, 0xF6D2B69C6F42BEDC, 0x39643EAF2CA2E4B4,
  0x22A81F139A2C9559, 0x5B3D6AEF0AF33807, 0x56E3F80A68643C08, 0x9E423BE502378780,
  0xCDB0986F9A5B2FD5, 0xD5B3C84E7933293F, 0xE5FB8C90399E9742, 0x5D393C1F77B2CF3D,
  0xC8C82F5B2FF09266, 0xACA0230CA6F7B593, 0xCB5805E2960D1655, 0x7E2AD5B704D77C95,
  0xC5E903CDB8B9EB5D, 0x4CC7D0D21CC03511, 0x8385DF382CFB3E93, 0xF17699D0564D348A,
  0xF77EE7F8274A4C8D, 0xB9D8CEE48903BABE, 0xFE0EBD2A82B9CFE9, 0xB49FB6397270F565,
  0x173735C8C342108E, 0xA37C7FBBEEC0A2EA, 0xC13F66F462BB0B6E, 0x0C04F3C2B551467E,
  0x76A9CB156810C96E, 0x2038850919B0B151, 0xCEA19F2B6EED647B, 0x6746656D2FA109A4,
  0xF05137F221007F37, 0x892FA9E13A3B4948, 0x4D57B70D37548A32, 0x1A7CFB3D566580E6,
  0x7CB30272A45E3FAC, 0x137CCFFD9D51423F, 0xB87D96F3B82DF266, 0x33349AEE7472ED37,
  0x5CC0D3C99555BC07, 0x4A8F4FA196D964EF, 0xE82A0D64F281FBFA, 0x38A1BAC2C36823E1,
  0x77D197C239FD737E, 0xFB07746B4E07DF26, 0xC8A2198E967672BD, 0x5F1A146D143FA05A,
  0x26B877A1201AB7AC, 0x74E5B145214723F8, 0xE9CE10E3C70254BC, 0x299393A0C05B79E8,
  0xFD2D2B9822A5E7E2, 0x85424FEA50C8E50A, 0xE6839E714B1FFFE5, 0x27971CCB46F9112A,
  0xC98695A2E0715AA9, 0x338E1CBB4F858226, 0xFC6B5C5CF7A8D806, 0x8973CAADDE8DA50C,
  0x9C6D47AE32EBAE72, 0x1EBF1F9F21D26D78, 0x80A9704B8E153859, 0x6AFD20A939F141FB,
  0xC35F6C2B3B553EEF, 0x59529E8B0DC94C1A, 0x1569DF036EBC4FA1, 0xDA32B88593C118F9,
  0xF01E4155FF5A5660, 0x765A2522DCE2B185, 0xCEE95554128073EF, 0x60F072A5CA51DE2F
};

static const uint64_t refval_32le[80] = {
  0x7C8D3555003E469A, 0x3681F9C3F1127CC8, 0xDBB713D2028227C2, 0x78771E7D21E489DA,
  0x8D659791EF3374FE, 0xCE9E6B054AB1C4A5, 0x846D50F82D595D82, 0x3639538046797CAA,
  0xB37E122F7392DE0A, 0xEE257CB10C794844, 0xF18B3919E8453962, 0x784AE8942A3E9904,
  0x2F80DD72243E2A0D, 0x1BD8419D553B6BED, 0x5ED2C2CFCE6B4E66, 0x979F14108B53422C,
  0x962DA10D015440AF, 0xB4AD7CEAFDFCBD6E, 0x226326258DD37B81, 0x565B0201832935A5,
  0x68373C98B9575D69, 0x29D4922ADD046615, 0xCD07D2669E26D2E8, 0x06FA9DCDC4828761,
  0x0BE3138F25EC4F45, 0x7A69F05F71894D63, 0xEF1F662FDBF2783D, 0x98C17BE571F52A51,
  0xD0500DD17A0366B5, 0x35AB2ABB09EEE627, 0xE0816D30DEC7987C, 0x9818488B7BC7B41C,
  0x8E7065C5518524DD, 0x20C65F2C8CBC9B3E, 0x7D08B202F425C39E, 0x60DC18CD911CAFC7,
  0x84CB42A883D23167, 0x6BFF2CF8AB705839, 0x41B644EF1101DE4B, 0x7A6944C48F818F25,
  0x7AA67961B1E8FF2C, 0x5BCA8BF67B3D2A11, 0x7F66C0B16E4A160B, 0x35DA1BEC148712A3,
  0x537715EDF8A0622C, 0xC34B43559C5D5440, 0x37D76AC5F07242C7, 0xBA4CB32425DD6BEB,
  0xBEA8FE3B935B8458, 0x88949A6B717DBD3F, 0x4B72D4A47CDC9341, 0xD792D3A694B1B0FE,
  0x186EF1351E6A0750, 0x81F4CDC9D6BB1DAC, 0x6AA7EDC1C2AE2E2C, 0x9CAAB63533410035,
  0x3014C6BF94AC4C77, 0x2CFCCBC761FA75F3, 0xF84BEF163C40D24F, 0x23BBDFAF810055DB,
  0xB936C93055260C8A, 0x5EF24667ECB9775F, 0x0CEC06141BE37147, 0x18FECAB3CB1F7DEA,
  0x1209B660972B0A88, 0xD19351CFD7E1A47C, 0xFF3BF60513833757, 0xDFE09FDAD9B2F85A,
  0x211A4745E3A2AF4B, 0xE3A33A114BE38F28, 0x5BCBB517074EED3A, 0xCC93F5820563E184,
  0xFEB29183724FC3A8, 0xCD99FE922F479963, 0xA38994893FF9CBBE, 0x60F593A497767EC0,
  0xF15203894864B213, 0x4DDB3C121175DF69, 0xFC102F9EDAA30ACE, 0x94E3531CBC1DDC97
};

static const uint64_t refval_32be[80] = {
  0x7C8D3555003E469A, 0xB67182BCAA37BD35, 0xDBB713D2028227C2, 0x29E8C60B04158480,
  0xC8301E0ABB6CA72A, 0x61A789243B057150, 0x7561E8B59EFDCCD3, 0x7CE51F527B4700BE,
  0xCB262ABA944284F3, 0xB2445D0304B96987, 0xBE3A0261E1346214, 0x84326AE0563FA723,
  0x7104EDC3683BE307, 0x5F6A6A51B826861E, 0x5C083F08DAD26389, 0x610AA7EC1E5629BF,
  0x5BC88B64C74823DA, 0x722C0E061B6ADF8D, 0xDEB26B204D5AF889, 0x01D35CA90DFCFC61,
  0xC4F667388834FD3A, 0xE1529168302D0DE7, 0x019D6BCD77C4D807, 0x1BDDADE9D492EFE0,
  0x993F06BA69041D9C, 0x4416CB009DCFB2A0, 0x9FC987E7DBE79F80, 0x3A76B9F2DC24376A,
  0x2C6DEB49516E30A1, 0x2205AD9041F8D9F3, 0x0E7058CA06F227F4, 0x0A6EB0AF8CE58789,
  0x7B72205F87E9ADD1, 0x870EA29548B10850, 0x8A815A513926CC37, 0x898374B5CDC36F49,
  0xBA24138146806BB2, 0x4FBC2261B5F71556, 0x769E1CCADF547147, 0x583DA9C726E5CD8E,
  0xE09BA92D16DA99B8, 0x9B5CC797FA7B7C1D, 0x3D79273B2D39668E, 0x05909A21D5C58AD1,
  0x9BB4DEDD3976D0FB, 0x755230444108C09E, 0xC75EFBE69A37494B, 0x4DA948AE8C0BC5E3,
  0x96F9A10FD5E355DA, 0x488A07BE48A68924, 0x93D65FA824F6D10A, 0x7D2C2CA3FD16143D,
  0xE9ACF05F50B3B631, 0x7F97964287F55F15, 0xD73EE29D102CD84E, 0x8F9F79D13C6475B1,
  0x34AA97BB089DAA38, 0xA3ECA0BC09D5708B, 0x2F3DF1A9F059E0D3, 0x18DC64B7CEB1CD14,
  0x7CE4E707AFA7E618, 0x109B40CDC5F1022C, 0xC52F79564FFF4C99, 0x9654AC2E296F1978,
  0x1C6F0C38B283B7C2, 0x6BF445DC9604BE69, 0x0D1BEEFB0421E124, 0xC12C8C8A95D98EBB,
  0xB96859EF9DB42DBA, 0xD0DFA46371271713, 0x233C6AF600EA3220, 0xD5588780552C6565,
  0x401F3751F212070D, 0xE6138263788254F7, 0x774E523D7F8FFA2F, 0xFE89384CE912D12C,
  0xA485F44080CDAB50, 0x07485C1AB5D2831D, 0x4AF2E5B8CA8EA0D7, 0x5918F4ED3485462E
};

#if defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) ||              \
    defined(i386) || defined(_X86_) || defined(__i386__) || defined(_X86_64_)
static const uint64_t refval_ia32aes_a[80] = {
  0x6a580668d6048674, 0x8400eaa9d99a9005, 0xe3ab9c06faf4d023, 0x6af1c60874c95442,
  0xb3557e561a6c5d82, 0x0ae73c696f3d37c0, 0x5ef25f7062324941, 0x9b784f3b4ce6af33,
  0x6993bb206a74f070, 0xf1e95df109076c4c, 0x4e1eb70c58e48540, 0x5fdd7649d8ec44e4,
  0x559122c706343421, 0x380133d58665e93d, 0x9ce74296c8c55ae4, 0x3556f9a5757ab6d0,
  0xf62751f7f25c469e, 0x851eec67f6516d94, 0xed463ee3848a8695, 0xdc8791feff8ed3ac,
  0x2569c744e1a282cf, 0xf90eb7c1d70a80b9, 0x68dfa6a1b8050a4c, 0x94cca5e8210d2134,
  0xf5cc0beabc259f52, 0x40dbc1f51618fda7, 0x0807945bf0fb52c6, 0xe5ef7e09de70848d,
  0x63e1df35febe994a, 0x2025e73769720d5a, 0xad6120b2b8a152e1, 0x2a71d9f13959f2b7,
  0x8a20849a27c32548, 0x0bcbc9fe3b57884e, 0xa7bf2ddd8f00efc0, 0xb080ba4ffe8c091b,
  0x95c723d82e9e5642, 0xde3e2155d51a2b97, 0xa797bebfea95c7b6, 0x66a04b1c6fcbe618,
  0x0c56ab810681a051, 0x8d1121337a565265, 0x862a3c70eeb20df6, 0xdeb9b38a4989407f,
  0xdba1cf225470e4d0, 0x5f5d52d3885dd1c6, 0xd8a842b32a2480ab, 0x9107908035f2c6de,
  0x9c129a478ca541c2, 0xedec764bfac4bab7, 0xa13dba75b355e511, 0x831dd972eb408603,
  0x2dbb16bf2d928bc9, 0xe3d796db0d12d23a, 0xdf5404c52cf35e52, 0x6748b200122b76cc,
  0x4b8149aafdaea1cf, 0xa01bb26c5f447179, 0x72c97ff21010d6bb, 0x3e6fef0a984a2095,
  0xeb77ebfc0a478c74, 0xf4350a4102478864, 0xbcdfb3555789d1ff, 0x6246e4f758e508da,
  0x8cf2f2d389542441, 0x3e695ca1865d2208, 0x6aaab8f6a7e8382f, 0xfeb2b25ac5d377ee,
  0xd71cb9ef6e6ad9dd, 0x25e50673c0339c0f, 0x1ad9a860235a74a2, 0xac2164169775843e,
  0xa5248411f9e2ffd6, 0xfe6873b7d696b46f, 0x7cebac5d4f9b4a1a, 0x5ca6312e4199250c,
  0x7a27e4ca25d951a6, 0x4986a4d2835186e4, 0x839d0b22d7782adf, 0xa87a89fa41833a00
};

static const uint64_t refval_ia32aes_b[80] = {
  0x6A580668D6048674, 0x8400EAA9D99A9005, 0xE3AB9C06FAF4D023, 0x6AF1C60874C95442,
  0xB3557E561A6C5D82, 0x0AE73C696F3D37C0, 0x5EF25F7062324941, 0x9B784F3B4CE6AF33,
  0x6993BB206A74F070, 0xF1E95DF109076C4C, 0x4E1EB70C58E48540, 0x5FDD7649D8EC44E4,
  0x559122C706343421, 0x380133D58665E93D, 0x9CE74296C8C55AE4, 0x3556F9A5757AB6D0,
  0xF62751F7F25C469E, 0x851EEC67F6516D94, 0xED463EE3848A8695, 0xDC8791FEFF8ED3AC,
  0x2569C744E1A282CF, 0xF90EB7C1D70A80B9, 0x68DFA6A1B8050A4C, 0x94CCA5E8210D2134,
  0xF5CC0BEABC259F52, 0x40DBC1F51618FDA7, 0x0807945BF0FB52C6, 0xE5EF7E09DE70848D,
  0x63E1DF35FEBE994A, 0x2025E73769720D5A, 0xAD6120B2B8A152E1, 0x2A71D9F13959F2B7,
  0x8A20849A27C32548, 0x0BCBC9FE3B57884E, 0xA7BF2DDD8F00EFC0, 0xB080BA4FFE8C091B,
  0x95C723D82E9E5642, 0xDE3E2155D51A2B97, 0xA797BEBFEA95C7B6, 0x66A04B1C6FCBE618,
  0x0C56AB810681A051, 0x8D1121337A565265, 0x862A3C70EEB20DF6, 0xDEB9B38A4989407F,
  0xDBA1CF225470E4D0, 0x5F5D52D3885DD1C6, 0xD8A842B32A2480AB, 0x9107908035F2C6DE,
  0x9C129A478CA541C2, 0x96BE74D0648425CF, 0x799411A7DEE1A5AA, 0x7DD3DAFB6FFA9FA1,
  0x6254D1E910037853, 0x0E7D66F901A0A28D, 0x7512F4034DEEB83E, 0xA98100FA36D06E9D,
  0x7BBC7C13961558CC, 0xD29283DF1F786E8A, 0x461BADAD5A64870B, 0x505CF0561F37E048,
  0x5A15964158B3BF1C, 0x870F80F9507259B6, 0x11DA16EE0507803B, 0xDF9FB89ED586FFAC,
  0x40EA802A0DC6EAF2, 0x7384D5FED96810B0, 0x3DAB55948E3CFA18, 0x961B9DF053FB6226,
  0xD5F398497BD71F91, 0xC6D30AC214F9C53E, 0xCB2966DE966D790A, 0x6AB7D42460A2D9AF,
  0xE53736761CD11758, 0xEB60C15D45991CC8, 0x2C4CE10BBA1F6330, 0x02F5B484E4AA8805,
  0xD671ED579D6185CF, 0x125700F2EFD42D3F, 0x0F8746461407741F, 0xC8878D76F1C0FCB6
};
#endif /* Any x86 */

/* *INDENT-ON* */
/* clang-format on */

#if defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) ||              \
    defined(i386) || defined(_X86_) || defined(__i386__) || defined(_X86_64_)

uint64_t t1ha0_ia32aes_noavx_a(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_noavx_b(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx_a(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx_b(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx2_a(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx2_b(const void *data, size_t length, uint64_t seed);

#ifdef __GNUC__
#include <cpuid.h>
#include <x86intrin.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#endif

int rdtscp_available;

static uint64_t x86_cpu_features(void) {
  uint32_t features = 0;
  uint32_t extended = 0;
  rdtscp_available = 0;
#ifdef __GNUC__
  uint32_t eax, ebx, ecx, edx;
  const unsigned cpuid_max = __get_cpuid_max(0, NULL);
  if (cpuid_max >= 1) {
    __cpuid(0x80000001, eax, ebx, ecx, edx);
    rdtscp_available = edx & (1 << 27);
    __cpuid_count(1, 0, eax, ebx, features, edx);
    if (cpuid_max >= 7)
      __cpuid_count(7, 0, eax, extended, ecx, edx);
  }
#elif defined(_MSC_VER)
  int info[4];
  __cpuid(info, 0);
  const unsigned cpuid_max = info[0];
  if (cpuid_max >= 1) {
    __cpuid(info, 0x80000001);
    rdtscp_available = info[3] & (1 << 27);
    __cpuidex(info, 1, 0);
    features = info[2];
    if (cpuid_max >= 7) {
      __cpuidex(info, 7, 0);
      extended = info[1];
    }
  }
#endif
  return features | (uint64_t)extended << 32;
}
#endif

/***************************************************************************/

#if defined(_X86_64_) || defined(__x86_64__) || defined(_M_X64) ||             \
    defined(__i386__) || defined(_M_IX86) || defined(i386) || defined(_X86_)

unsigned bench(const char *caption,
               uint64_t (*hash)(const void *, size_t, uint64_t),
               const void *data, unsigned len, uint64_t seed) {

  printf("%24s: ", caption);
  fflush(NULL);

  uint64_t min_ticks = UINT64_MAX;
  unsigned stable_counter = 0;

  unsigned start_cpu, stop_cpu;
  uint64_t start_tsc, stop_tsc;

  while (1) {
    int unused[4];
#ifdef _MSC_VER
    __cpuid(unused, 0);
#else
    __cpuid(0, unused[0], unused[1], unused[2], unused[3]);
#endif

    start_tsc = __rdtscp(&start_cpu);
    hash(data, len, seed);
    stop_tsc = __rdtscp(&stop_cpu);
#ifdef _MSC_VER
    __cpuid(unused, 0);
#else
    __cpuid(0, unused[0], unused[1], unused[2], unused[3]);
#endif

    if (start_cpu != stop_cpu || stop_tsc <= start_tsc)
      continue;

    uint64_t ticks = stop_tsc - start_tsc;
    if (min_ticks > ticks) {
      min_ticks = ticks;
      stable_counter = 0;
      continue;
    }

    if (++stable_counter == 10000)
      break;
  }

  printf("%7" PRIu64 " ticks, %7.4f clk/byte, %7.3f Mb/s @3GHz\n", min_ticks,
         (double)min_ticks / len, 3.0 * len / min_ticks);
  fflush(NULL);

  return (min_ticks < INT32_MAX) ? (unsigned)min_ticks : UINT32_MAX;
}

#endif /* x86 for t1ha_ia32aes */

/***************************************************************************/

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  int failed = 0;
  failed |= test("t1ha1_64le", t1ha1_le, refval_64le);
  failed |= test("t1ha1_64be", t1ha1_be, refval_64be);
  failed |= test("t1ha0_32le", t1ha0_32le, refval_32le);
  failed |= test("t1ha0_32be", t1ha0_32be, refval_32be);

#if defined(_X86_64_) || defined(__x86_64__) || defined(_M_X64) ||             \
    defined(__i386__) || (defined(_M_IX86) && _MSC_VER > 1800) ||              \
    defined(i386) || defined(_X86_)

  const uint64_t features = x86_cpu_features();
  if (features & UINT32_C(0x02000000)) {
    failed |=
        test("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, refval_ia32aes_a);
    if ((features & UINT32_C(0x1A000000)) == UINT32_C(0x1A000000)) {
      failed |= test("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, refval_ia32aes_a);
      if ((features >> 32) & 32)
        failed |=
            test("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2, refval_ia32aes_b);
    }
  }

#if !defined(__OPTIMIZE__) && (defined(_MSC_VER) && defined(_DEBUG))
  printf("\nNon-optimized/Debug build, skip benchmark\n");
#else
  if (!rdtscp_available) {
    printf("\nNo RDTSCP available on CPU, skip benchmark\n");
  } else {
    const unsigned large = 1024 * 256;
    const unsigned medium = 127;
    const unsigned small = 31;
    char *buffer = malloc(large);
    for (unsigned i = 0; i < large; ++i)
      buffer[i] = (char)(rand() + i);

    printf("\nSimple bench for x86 (large keys, %u bytes):\n", large);
    bench("t1ha1_64le", t1ha1_le, buffer, large, 42);
    bench("t1ha1_64be", t1ha1_be, buffer, large, 42);
    bench("t1ha0_32le", t1ha0_32le, buffer, large, 42);
    bench("t1ha0_32be", t1ha0_32be, buffer, large, 42);

    printf("\nSimple bench for x86 (small keys, %u bytes):\n", small);
    bench("t1ha1_64le", t1ha1_le, buffer, small, 42);
    bench("t1ha1_64be", t1ha1_be, buffer, small, 42);
    bench("t1ha0_32le", t1ha0_32le, buffer, small, 42);
    bench("t1ha0_32be", t1ha0_32be, buffer, small, 42);

    if (features & UINT32_C(0x02000000)) {
      printf("\nSimple bench for AES-NI (medium keys, %u bytes):\n", medium);
      bench("t1ha0_ia32aes_noavx_a", t1ha0_ia32aes_noavx_a, buffer, medium, 42);
      bench("t1ha0_ia32aes_noavx_b", t1ha0_ia32aes_noavx_b, buffer, medium, 42);
      bench("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, buffer, medium, 42);
      if ((features & UINT32_C(0x1A000000)) == UINT32_C(0x1A000000)) {
        bench("t1ha0_ia32aes_avx_a", t1ha0_ia32aes_avx_a, buffer, medium, 42);
        bench("t1ha0_ia32aes_avx_b", t1ha0_ia32aes_avx_b, buffer, medium, 42);
        bench("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, buffer, medium, 42);
        if ((features >> 32) & 32) {
          bench("t1ha0_ia32aes_avx2_a", t1ha0_ia32aes_avx2_a, buffer, medium,
                42);
          bench("t1ha0_ia32aes_avx2_b", t1ha0_ia32aes_avx2_b, buffer, medium,
                42);
          bench("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2, buffer, medium, 42);
        }
      }

      printf("\nSimple bench for AES-NI (large keys, %u bytes):\n", large);
      bench("t1ha0_ia32aes_noavx_a", t1ha0_ia32aes_noavx_a, buffer, large, 42);
      bench("t1ha0_ia32aes_noavx_b", t1ha0_ia32aes_noavx_b, buffer, large, 42);
      bench("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, buffer, large, 42);
      if ((features & UINT32_C(0x1A000000)) == UINT32_C(0x1A000000)) {
        bench("t1ha0_ia32aes_avx_a", t1ha0_ia32aes_avx_a, buffer, large, 42);
        bench("t1ha0_ia32aes_avx_b", t1ha0_ia32aes_avx_b, buffer, large, 42);
        bench("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, buffer, large, 42);
        if ((features >> 32) & 32) {
          bench("t1ha0_ia32aes_avx2_a", t1ha0_ia32aes_avx2_a, buffer, large,
                42);
          bench("t1ha0_ia32aes_avx2_b", t1ha0_ia32aes_avx2_b, buffer, large,
                42);
          bench("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2, buffer, large, 42);
        }
      }
    }

    free(buffer);
  }
#endif /* __OPTIMIZE__ */
#endif /* x86 for t1ha_ia32aes */

  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
