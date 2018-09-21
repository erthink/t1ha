/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
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

#include "../common.h"
#include "stadtx_hash.h"

uint64_t thunk_StadtX(const void *input, size_t length, uint64_t seed) {
  uint64_t state[4] = {seed, seed, seed, seed};
  return stadtx_hash_with_state(state, input, length);
}

/* *INDENT-OFF* */
/* clang-format off */
const uint64_t refval_StadtX[81] = { 0x1D8FDD3902761988,
  0x3E73CCEA8E7BD54E, 0xA43590A0D6F8C2E5, 0x7D3D74C2D6259671, 0xD7208FDA176BB9D2,
  0x001DAB349BE63C03, 0xDE0B7C82898ECECD, 0xA2B6C896B799DB01, 0x668A589EFD80D2EA,
  0xCDF2E57587745456, 0x56F69ED9BA2D20BE, 0x0B13A4425AF3F03B, 0x4C84D86118CDAC49,
  0xF2A7F9EBA65C76E8, 0xEEDE04FF04ED7F52, 0xC1BD47E8E384A965, 0xE3BA60B1B3C00B21,
  0x2C08F618D6430962, 0x462CFF45FEBDC320, 0x97B0484A7B28A710, 0x36E941F33D42AAEB,
  0xED4C0116E649985F, 0xF1F34BA1B5F39635, 0x1F1AA01DCFAA1173, 0x9F61B2CF31B9B4C3,
  0x115B4048147C3684, 0x1C0E0768A16B6464, 0x3DDBE38A80A51F63, 0x705FD8A4EFB19585,
  0xB73012A80F64D66C, 0x6FD48B29F3C6D139, 0x56CF356428A43889, 0x4B858D94E9DECDBA,
  0x81EDB9F56373AC80, 0xF60BF2ECDCABECC6, 0x8ABDCCB98B998133, 0x085F1C19F547EADC,
  0xCB435795F64E9553, 0x316FC6F580388FBE, 0x1B0E8FE6FB7EA1E7, 0xFB3A2C79D53A2B2D,
  0x6470C632D75ADF36, 0x3B5E28ED0C39A53D, 0x63963B97BD6FACBA, 0x271932D82564C326,
  0x76972A129F6BB4D0, 0x4478443177161BAE, 0x241C98736A3C7D8F, 0xC53E0DF5151F4335,
  0x08D079ED3C7BC23F, 0x8933C4E5216472C1, 0xAEAEFDDAD4111C76, 0xA7B51A722A85E8E4,
  0x08B0E5A1B46C275A, 0x55881D991E32B4E7, 0x6C725B1B8FDD598D, 0x9797C7C03BA0492E,
  0xA1072974BF576D37, 0x610A517B2A6FD168, 0x64328409659C86C5, 0x88DF17915E00C40A,
  0xA6B5F8FFF65C2C0F, 0xD40CBCAC358DEC32, 0x02115A34E6A0ED62, 0xAA83E7415E9F40C0,
  0x3A54A2CFFCCDB157, 0x7759C39A6EB25EB5, 0x7BA43A2BD2FCF2E0, 0x267B3FC1DFCBCF48,
  0x938113D2808C9755, 0x9B7DB24F2F8AE5BE, 0xC4ADCEE6AF5353DC, 0xDD57A317D32ABE13,
  0x55BE7E43FACA96DC, 0x7442CABF0D0B46AE, 0xA5052ACBF7B1F40C, 0xA80CBC3FA292FB8A,
  0xF7C5FD3F347C1718, 0x93E2F9C5471F8524, 0xFB130F138ED9E665, 0x41736945A6E44A8E
};
/* *INDENT-ON* */
/* clang-format on */
