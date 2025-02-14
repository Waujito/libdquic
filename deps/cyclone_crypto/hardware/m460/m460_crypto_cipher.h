/**
 * @file m460_crypto_cipher.h
 * @brief M460 cipher hardware accelerator
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2025 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.5.0
 **/

#ifndef _M460_CRYPTO_CIPHER_H
#define _M460_CRYPTO_CIPHER_H

//Dependencies
#include "core/crypto.h"

//Cipher hardware accelerator
#ifndef M460_CRYPTO_CIPHER_SUPPORT
   #define M460_CRYPTO_CIPHER_SUPPORT DISABLED
#elif (M460_CRYPTO_CIPHER_SUPPORT != ENABLED && M460_CRYPTO_CIPHER_SUPPORT != DISABLED)
   #error M460_CRYPTO_CIPHER_SUPPORT parameter is not valid
#endif

//OPMODE bitfield
#define CRPT_AES_CTL_OPMODE_ECB     0x00000000
#define CRPT_AES_CTL_OPMODE_CBC     0x00000100
#define CRPT_AES_CTL_OPMODE_CFB     0x00000200
#define CRPT_AES_CTL_OPMODE_OFB     0x00000300
#define CRPT_AES_CTL_OPMODE_CTR     0x00000400
#define CRPT_AES_CTL_OPMODE_CBC_CS1 0x00001000
#define CRPT_AES_CTL_OPMODE_CBC_CS2 0x00001100
#define CRPT_AES_CTL_OPMODE_CBC_CS3 0x00001200
#define CRPT_AES_CTL_OPMODE_GCM     0x00002000
#define CRPT_AES_CTL_OPMODE_GHASH   0x00002100
#define CRPT_AES_CTL_OPMODE_CCM     0x00002200

//KEYSZ bitfield
#define CRPT_AES_CTL_KEYSZ_128B     0x00000000
#define CRPT_AES_CTL_KEYSZ_192B     0x00000004
#define CRPT_AES_CTL_KEYSZ_256B     0x00000008

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
