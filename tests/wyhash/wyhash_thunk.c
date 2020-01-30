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

uint64_t thunk_wyhash_v4(const void *input, size_t length, uint64_t seed) {
  return wyhash(input, length, seed);
}

/* *INDENT-OFF* */
/* clang-format off */
const uint64_t refval_wyhash_v4[81] = { 0,
  0xFFFFFFFFFFFFFFFF, 0x7E298DE73A6275B5, 0xCD97719EFF7737D0, 0x8ADE39929F41D720,
  0x5A5CDD5C67ADB95A, 0x4BC78AAD3B18F979, 0x6CC91E6B74CA84EB, 0x3095FCBC0856C32C,
  0x5C4C2354E6DDEBBF, 0xA9B9F1DB9C5CC202, 0x4FF42B11B4B35A1A, 0x42C35A1D4648D4FA,
  0x2908CA110693EA54, 0x8B384D613F15B181, 0x9ED4EAECA8AD6F85, 0xCF0E16A13EED4C30,
  0xC2CBAE25EA6C70AB, 0xCF51E754E2516D6C, 0x8FB318536CFE56DE, 0xF276918F681A5786,
  0x750A773D095D168F, 0x8FD0440239922074, 0x1DACBE198C7EA6F3, 0xFEB14123C392EEB4,
  0x236A9366BFABBC9C, 0x433720A2148312DF, 0x0D0402BD949AD02F, 0x2729A0E73B4A54EC,
  0x836C978CF6AA406D, 0x36A2218ECD100C63, 0x9CD7A9EA8E064C99, 0xECD3F80C1B4616D5,
  0x60F276F10BFD63E7, 0x5F22A181C1CE8F51, 0xA52ACAF86FE992FB, 0x283E3DC0E9E42B84,
  0x874CE45AA4739CA1, 0x20E3C3FC7C3F6FD8, 0xBD4DABE9B8FAD0BD, 0x66688EB8C69179FE,
  0xAFDBCC79BC4B5ED9, 0xDF77D9E19437A490, 0x05BD206A9A262853, 0x49D9C37D04C4C9EA,
  0x72631FC4FC822C78, 0xA765A10D851FF0CA, 0x38927CB542870985, 0x5A1D670236C25A58,
  0x8F913631818835C9, 0x6FEA2BF12494B0B1, 0xAA686D76FC68E095, 0x72E7A7788DF89B20,
  0x8B42BD24696F8FA6, 0xB6E33D0A5ABF3BCD, 0x98DCCA5950F6D0EE, 0x7120A9B29B121A25,
  0x455D059266948A58, 0xEF6A540B9BB05CB6, 0x171C690401C64BBD, 0xA4F383987384BF6A,
  0x8608E530745D827F, 0xADE43EBE2B4D6EEC, 0x6C27BA911D0BFFDC, 0x4015B34E75708497,
  0xC2476227A2F75217, 0x2550EFF554E75169, 0x03EA3C7FECB2A7F3, 0xA77D8C5653398611,
  0x807AFDF9CF09981B, 0x99E76AD0D103228A, 0x66314D68FC65194C, 0x948E66CE902BD768,
  0x7B8B7A91D1A8C4E1, 0x0A19012A41F2ABD2, 0xA11A25D7DCF43C54, 0xB9632E52A105F1A0,
  0xCDA357F4562A9F81, 0xFA9436067F572E53, 0x7146E426093A4663, 0x438449B824315525
};
/* *INDENT-ON* */
/* clang-format on */
