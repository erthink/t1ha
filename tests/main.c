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
#include <stdbool.h> /* for bool */
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

bool verbose, skip;

bool probe(uint64_t (*hash)(const void *, size_t, uint64_t),
           const char *caption, const uint64_t check, const void *data,
           unsigned len, uint64_t seed) {
  uint64_t value = hash(data, len, seed);
  if (verbose || (value != check && !skip))
    printf("Pattern '%s', reference value %08X%08X: ", caption,
           (uint32_t)(check >> 32), (uint32_t)check);
  if (check == value) {
    if (verbose)
      printf("Passed\n");
    return false;
  }
  if (!skip)
    printf("Failed! Got %08X%08X\n", (uint32_t)(value >> 32), (uint32_t)value);
  return true;
}

bool test(const char *title, uint64_t (*hash)(const void *, size_t, uint64_t),
          const uint64_t *reference_values) {
  printf("Testing %s...%s", title, verbose ? "\n" : "");

  const uint64_t zero = 0;
  bool failed = false;
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

  printf(" %s\n", (!verbose && !failed) ? "Ok" : (skip ? "Skipped" : ""));
  return failed && !skip;
}

/* *INDENT-OFF* */
/* clang-format off */
static const uint64_t refval_2atonce[80] = { 0 };
static const uint64_t refval_2atonce128[80] = { 0 };
static const uint64_t refval_2stream[80] = { 0 };
static const uint64_t refval_2stream128[80] = { 0 };

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
  0xC92229C10FAEA50E, 0x3DF1354B0DFDC443, 0x968F016D60417BB3, 0x85AAFB50C6DA770F,
  0x66CCE3BB6842C7D6, 0xDDAA39C11537C226, 0x35958D281F0C9C8C, 0x8C5D64B091DE608E,
  0x4094DF680D39786B, 0x1014F4AA2A2EDF4D, 0x39D21891615AA310, 0x7EF51F67C398C7C4,
  0x06163990DDBF319D, 0xE229CAA00C8D6F3F, 0xD2240B4B0D54E0F5, 0xEA2E7E905DDEAF94,
  0x8D4F8A887183A5CE, 0x44337F9A63C5820C, 0x94938D1E86A9B797, 0x96E9CABA5CA210CC,
  0x6EFBB9CC9E8F7708, 0x3D12EA0282FB8BBC, 0x5DA781EE205A2C48, 0xFA4A51A12677FE12,
  0x81D5F04E20660B28, 0x57258D043BCD3841, 0x5C9BEB62059C1ED2, 0x57A02162F9034B33,
  0xBA2A13E457CE19B8, 0xE593263BF9451F3A, 0x0BC1175539606BC5, 0xA3E2929E9C5F289F,
  0x86BDBD06835E35F7, 0xA180950AB48BAADC, 0x7812C994D9924028, 0x308366011415F46B,
  0x77FE9A9991C5F959, 0x925C340B70B0B1E3, 0xCD9C5BA4C41E2E10, 0x7CC4E7758B94CD93,
  0x898B235962EA4625, 0xD7E3E5BF22893286, 0x396F4CDD33056C64, 0x740AB2E32F17CD9F,
  0x60D12FF9CD15B321, 0xBEE3A6C9903A81D8, 0xB47040913B33C35E, 0x19EE8C2ACC013CFF,
  0x5DEC94C5783B55C4, 0x78DC122D562C5F1D, 0x6520F008DA1C181E, 0x77CAF155A36EBF7C,
  0x0A09E02BDB883CA6, 0xFD5D9ADA7E3FB895, 0xC6F5FDD9EEAB83B5, 0x84589BB29F52A92A,
  0x9B2517F13F8E9814, 0x6F752AF6A52E31EC, 0x8E717799E324CE8A, 0x84D90AEF39262D58,
  0x79C27B13FC28944D, 0xE6D6DF6438E0044A, 0x51B603E400D79CA4, 0x6A902B28C588B390,
  0x8D7F8DE9E6CB1D83, 0xCF1A4DC11CA7F044, 0xEF02E43C366786F1, 0x89915BCDBCFBE30F,
  0x5928B306F1A9CC7F, 0xA8B59092996851C5, 0x22050A20427E8B25, 0x6E6D64018941E7EE,
  0x9798C898B81AE846, 0x80EF218CDC30124A, 0xFCE45E60D55B0284, 0x4010E735D3147C35,
  0xEB647D999FD8DC7E, 0xD3544DCAB14FE907, 0xB588B27D8438700C, 0xA49EBFC43E057A4C
};

static const uint64_t refval_32be[80] = {
  0xC92229C10FAEA50E, 0x0FE212630DD87E0F, 0x968F016D60417BB3, 0xE6B12B2C889913AB,
  0xAA3787887A9DA368, 0x06EE7202D53CEF39, 0x6149AFB2C296664B, 0x86C893210F9A5805,
  0x8379E5DA988AA04C, 0x24763AA7CE411A60, 0x9CF9C64B395A4CF8, 0xFFC192C338DDE904,
  0x094575BAB319E5F5, 0xBBBACFE7728C6511, 0x36B8C3CEBE4EF409, 0xAA0BA8A3397BA4D0,
  0xF9F85CF7124EE653, 0x3ADF4F7DF2A887AE, 0xAA2A0F5964AA9A7A, 0xF18B563F42D36EB8,
  0x034366CEF8334F5C, 0xAE2E85180E330E5F, 0xA5CE9FBFDF5C65B8, 0x5E509F25A9CA9B0B,
  0xE30D1358C2013BD2, 0xBB3A04D5EB8111FE, 0xB04234E82A15A28D, 0x87426A56D0EA0E2F,
  0x095086668E07F9F8, 0xF4CD3A43B6A6AEA5, 0x73F9B9B674D472A6, 0x558344229A1E4DCF,
  0x0AD4C95B2279181A, 0x5E3D19D80821CA6B, 0x652492D25BEBA258, 0xEFA84B02EAB849B1,
  0x81AD2D253059AC2C, 0x1400CCB0DFB2F457, 0x5688DC72A839860E, 0x67CC130E0FD1B0A7,
  0x0A851E3A94E21E69, 0x2EA0000B6A073907, 0xAE9776FF9BF1D02E, 0xC0A96B66B160631C,
  0xA93341DE4ED7C8F0, 0x6FBADD8F5B85E141, 0xB7D295F1C21E0CBA, 0x6D6114591B8E434F,
  0xF5B6939B63D97BE7, 0x3C80D5053F0E5DB4, 0xAC520ACC6B73F62D, 0xD1051F5841CF3966,
  0x62245AEA644AE760, 0x0CD56BE15497C62D, 0x5BB93435C4988FB6, 0x5FADB88EB18DB512,
  0xC897CAE2242475CC, 0xF1A094EF846DC9BB, 0x2B1D8B24924F79B6, 0xC6DF0C0E8456EB53,
  0xE6A40128303A9B9C, 0x64D37AF5EFFA7BD9, 0x90FEB70A5AE2A598, 0xEC3BA5F126D9FF4B,
  0x3121C8EC3AC51B29, 0x3B41C4D422166EC1, 0xB4878DDCBF48ED76, 0x5CB850D77CB762E4,
  0x9A27A43CC1DD171F, 0x2FDFFC6F99CB424A, 0xF54A57E09FDEA7BB, 0x5F78E5EE2CAB7039,
  0xB8BA95883DB31CBA, 0x131C61EB84AF86C3, 0x84B1F64E9C613DA7, 0xE94C1888C0C37C02,
  0xEA08F8BFB2039CDE, 0xCCC6D04D243EC753, 0x8977D105298B0629, 0x7AAA976494A5905E
};

#ifdef T1HA_IA32_AVAILABLE
static const uint64_t refval_ia32aes_a[80] = {
  0x4DE42DAE10FAB4D6, 0x25AADCE36A1D661D, 0xD9F87681CBBD0526, 0x2AD24CCD17D8478A,
  0xBEB68103CE241ADF, 0x42B2C3EF775510E0, 0x1AEB8CA76C60DF39, 0xBD89A22CC2CFC161,
  0xC9CC8776DDA201AE, 0xE9B5730ECED0640D, 0xFA583E80415DF517, 0xD14FD86B99B92568,
  0xB8FC5FF073B937CD, 0x9B52A784C080E2CD, 0x43427B17CE1DB298, 0x44A0E4A6E7BD711A,
  0x8308C524AA7A7228, 0x23920657A8098843, 0x6C4140FD51D8C615, 0x53792DCD4E52B7EF,
  0x3C848A6B9AC4DA10, 0xBD5F6D44E9521F9D, 0x4179457E4A34B2A5, 0xEF9EBA58FF11E1E7,
  0x7267D911FDA5557E, 0x7D9C816C9044A80B, 0x25C8EB0A398B3062, 0x0A1E93427F7B2915,
  0x7DB5CA8D6E37EC02, 0x34B8B285CBC5BE3A, 0x69161B6127B797CA, 0x7A7B7F1FEF8B084E,
  0xFA2DB97F991BFBAA, 0xCF1F1A82552B9E86, 0x9B511267BA1CCE27, 0xD197DAECE9B3D27A,
  0xBC64E58C2988E59E, 0xF3CF671E9B2A3548, 0xFA549C847F17EF4F, 0x1A59A80ADA1AE00D,
  0x3CEF4C0DFF35620F, 0x433ADEA54C8640A8, 0x5B1D0FA6CC79B5A9, 0x9FA9CB034B25F9B2,
  0x9EC99111D81360AD, 0x36A8CC1FD35152A0, 0x173DEE82492790C0, 0x4AA10EB85F617F97,
  0xD8A358CFB0CE6409, 0x32D957C1685642AF, 0xDC62C7CF939079CA, 0x4260CFDF9D974C27,
  0x9F7A3A55DFF6FDB2, 0x246F49474C2CB422, 0x3C38CA30957A58C5, 0x4027B3828D491331,
  0xE968491A168ED9F6, 0x5BA8F1ADC8BE38E7, 0xBC00A845F6810C2F, 0xFB48040A3E1A7A01,
  0x9D1B4F61400E2D02, 0xD6D58AB09E457B02, 0x6EBF825946E6CE61, 0xC45F54465B838DA3,
  0xF44EAB67BA035DD4, 0x3AD48533CE4E0B47, 0x0AEB3D7B13715FC1, 0xB0C3B79F060397EB,
  0x3A4644623B9B0D60, 0x0671C04036DD4288, 0xC3A863122747D236, 0x30A88948A50A5B75,
  0x98873D6517E35C0B, 0x2D46F881EC7B3840, 0xCD1361A23B083C31, 0x0CC06B4624E087A3,
  0x5A42DEABB396266C, 0x663262CB32B7B6AC, 0x241F5BC2A1430D39, 0xC34697D55EFB8870
};

static const uint64_t refval_ia32aes_b[80] = {
  0x4DE42DAE10FAB4D6, 0xD43E785727EC1D9E, 0xD9F87681CBBD0526, 0x2AD24CCD17D8478A,
  0xBEB68103CE241ADF, 0x42B2C3EF775510E0, 0x1AEB8CA76C60DF39, 0xBD89A22CC2CFC161,
  0xC9CC8776DDA201AE, 0xE9B5730ECED0640D, 0xFA583E80415DF517, 0xD14FD86B99B92568,
  0xB8FC5FF073B937CD, 0x9B52A784C080E2CD, 0x43427B17CE1DB298, 0x44A0E4A6E7BD711A,
  0x8308C524AA7A7228, 0x23920657A8098843, 0x6C4140FD51D8C615, 0x53792DCD4E52B7EF,
  0x3C848A6B9AC4DA10, 0xBD5F6D44E9521F9D, 0x4179457E4A34B2A5, 0xEF9EBA58FF11E1E7,
  0x7267D911FDA5557E, 0x7D9C816C9044A80B, 0x25C8EB0A398B3062, 0x0A1E93427F7B2915,
  0x7DB5CA8D6E37EC02, 0x34B8B285CBC5BE3A, 0x69161B6127B797CA, 0x7A7B7F1FEF8B084E,
  0xFA2DB97F991BFBAA, 0xCF1F1A82552B9E86, 0xB1EC30600158F822, 0x7745A5E33A3175EC,
  0x949A5BE442367602, 0xBCECF5432DED84E1, 0x09DEE25C9D65BDC5, 0x3C14E4B79C468E8D,
  0x4CC9AB040C9D4C8F, 0x04BC9E95BD383080, 0x5B7AC3EAA1B3827E, 0x10E477DABDF6A843,
  0x698B0EE3005A8A65, 0xAFEBACD7426BF719, 0xEDEAC47FC1C0943A, 0xC5521F0F1A5FFDE2,
  0x31411EFE68C3BDC3, 0x7A5BD5EDB67BD60C, 0x5F71037F14F9C428, 0x59A8259217EB21D7,
  0x118B96798754CF30, 0x3FCEC3938A4CCF67, 0x0A94BB72D725DAEC, 0xF09F083E6A1F8B14,
  0x8C2D648E4DF0DB26, 0x2B4E180C329B1CFF, 0x16A95A883BB3690A, 0xA88683F684D992CE,
  0x9E3ED2548B4F005A, 0x107C1A605D8BAAA7, 0x973622469C33DF92, 0xA54DDD3CF427350F,
  0x69BEA60020B04DDE, 0x5554361339F89750, 0xAC3D8061633BEEF2, 0x348E9D500DF11963,
  0xACFFB1554958CC8C, 0x610264D4DE0BA521, 0xAC3C1B39797369CB, 0x923DFD113643F7F2,
  0xF7DAF53D53ACBF96, 0x95BCB6B815FF253B, 0xAB2E53FD00ABA0EE, 0x574C120B0968CC0B,
  0x4AFBBFA6897A67DF, 0x95A76119140DC64B, 0xEC7F244BD901BA23, 0x8E258FE7DA53451D
};
#endif /* T1HA_IA32_AVAILABLE */

/* *INDENT-ON* */
/* clang-format on */

#ifdef T1HA_IA32_AVAILABLE

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

bool rdtscp_available;

static uint64_t x86_cpu_features(void) {
  uint32_t features = 0;
  uint32_t extended = 0;
  rdtscp_available = false;
#ifdef __GNUC__
  uint32_t eax, ebx, ecx, edx;
  const unsigned cpuid_max = __get_cpuid_max(0, NULL);
  if (cpuid_max >= 1) {
    __cpuid(0x80000001, eax, ebx, ecx, edx);
    rdtscp_available = (edx & (1 << 27)) ? true : false;
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

#endif /* T1HA_IA32_AVAILABLE */

/***************************************************************************/

static uint64_t thunk_t1ha2_atonce128(const void *data, size_t len,
                                      uint64_t seed) {
  uint64_t unused;
  return t1ha2_atonce128(&unused, data, len, seed);
}

static uint64_t thunk_t1ha2_stream(const void *data, size_t len,
                                   uint64_t seed) {
  t1ha_context_t ctx;
  t1ha2_init(&ctx, seed, seed);
  t1ha2_update(&ctx, data, len);
  return t1ha2_final(&ctx, NULL);
}

static uint64_t thunk_t1ha2_stream128(const void *data, size_t len,
                                      uint64_t seed) {
  t1ha_context_t ctx;
  t1ha2_init(&ctx, seed, seed);
  t1ha2_update(&ctx, data, len);
  uint64_t unused;
  return t1ha2_final(&ctx, &unused);
}

#ifdef T1HA_IA32_AVAILABLE

unsigned bench(const char *caption,
               uint64_t (*hash)(const void *, size_t, uint64_t),
               const void *data, unsigned len, uint64_t seed) {

  printf("%-24s: ", caption);
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

  printf("%7" PRIu64 " ticks, %7.3f clk/byte, %7.3f Gb/s @3GHz\n", min_ticks,
         (double)min_ticks / len, 3.0 * len / min_ticks);
  fflush(NULL);

  return (min_ticks < INT32_MAX) ? (unsigned)min_ticks : UINT32_MAX;
}

enum bench_flags {
  bench_32 = 1 << 1,
  bench_64 = 1 << 2,
  bench_le = 1 << 3,
  bench_be = 1 << 4,
  bench_aes = 1 << 5,
  bench_avx = 1 << 6,
  bench_avx2 = 1 << 7,
};

static bool is_set(unsigned value, unsigned mask) {
  return (value & mask) == mask;
}

static void bench_size(const unsigned size, const char *caption,
                       const unsigned bench_flags) {
  printf("\nSimple bench for x86 (%s keys, %u bytes):\n", caption, size);
  const uint64_t seed = 42;
  char *buffer = malloc(size);
  for (unsigned i = 0; i < size; ++i)
    buffer[i] = (char)(rand() + i);

  if (is_set(bench_flags, bench_64 | bench_le)) {
    bench("t1ha2_atonce", t1ha2_atonce, buffer, size, seed);
    bench("t1ha2_atonce128", thunk_t1ha2_atonce128, buffer, size, seed);
    bench("t1ha2_stream", thunk_t1ha2_stream, buffer, size, seed);
    bench("t1ha2_stream128", thunk_t1ha2_stream128, buffer, size, seed);
    bench("t1ha1_64le", t1ha1_le, buffer, size, seed);
  }
  if (is_set(bench_flags, bench_64 | bench_be))
    bench("t1ha1_64be", t1ha1_be, buffer, size, seed);
  if (is_set(bench_flags, bench_32 | bench_le))
    bench("t1ha0_32le", t1ha0_32le, buffer, size, seed);
  if (is_set(bench_flags, bench_32 | bench_be))
    bench("t1ha0_32be", t1ha0_32be, buffer, size, seed);

  if (bench_flags & bench_aes) {
    bench("t1ha0_ia32aes_noavx_a", t1ha0_ia32aes_noavx_a, buffer, size, seed);
    bench("t1ha0_ia32aes_noavx_b", t1ha0_ia32aes_noavx_b, buffer, size, seed);
    bench("t1ha0_ia32aes_noavx", t1ha0_ia32aes_noavx, buffer, size, seed);
    if (bench_flags & bench_avx) {
      bench("t1ha0_ia32aes_avx_a", t1ha0_ia32aes_avx_a, buffer, size, seed);
      bench("t1ha0_ia32aes_avx_b", t1ha0_ia32aes_avx_b, buffer, size, seed);
      bench("t1ha0_ia32aes_avx", t1ha0_ia32aes_avx, buffer, size, seed);
    }
    if (bench_flags & bench_avx2) {
      bench("t1ha0_ia32aes_avx2_a", t1ha0_ia32aes_avx2_a, buffer, size, seed);
      bench("t1ha0_ia32aes_avx2_b", t1ha0_ia32aes_avx2_b, buffer, size, seed);
      bench("t1ha0_ia32aes_avx2", t1ha0_ia32aes_avx2, buffer, size, seed);
    }
  }

  free(buffer);
}
#endif /* T1HA_IA32_AVAILABLE */

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  bool failed = false;

  skip = true;
  failed |= test("t1ha2_atonce", t1ha2_atonce, refval_2atonce);
  failed |= test("t1ha2_atonce128", thunk_t1ha2_atonce128, refval_2atonce128);
  failed |= test("t1ha2_stream", thunk_t1ha2_stream, refval_2stream);
  failed |= test("t1ha2_stream128", thunk_t1ha2_stream128, refval_2stream128);
  skip = false;
  failed |= test("t1ha1_64le", t1ha1_le, refval_64le);
  failed |= test("t1ha1_64be", t1ha1_be, refval_64be);
  failed |= test("t1ha0_32le", t1ha0_32le, refval_32le);
  failed |= test("t1ha0_32be", t1ha0_32be, refval_32be);

#ifdef T1HA_IA32_AVAILABLE

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
    unsigned bench_all = ~0u;
    if ((features & UINT32_C(0x02000000)) == 0)
      bench_all -= bench_aes;
    if ((features & UINT32_C(0x1A000000)) != UINT32_C(0x1A000000))
      bench_all -= bench_avx;
    if (((features >> 32) & 32) == 0)
      bench_all -= bench_avx2;

    bench_size(5, "tiny", bench_all);
    bench_size(31, "small", bench_all & ~(bench_be | bench_32));
    bench_size(1024, "medium", bench_all & ~(bench_be | bench_32));
    bench_size(1024 * 256, "large", bench_all);
  }
#endif /* __OPTIMIZE__ */
#endif /* T1HA_IA32_AVAILABLE */

  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
