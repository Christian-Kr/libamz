/* Copyright (c) 2012 Christian Krippendorf <Coding@Christian-Krippendorf.de>
 *
 * This file is part of libamz.
 *
 * libamz is free software: you can redistribute it and/or modify it under the terms of the GNU
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * libamz is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with libamz.  If not, see
 * <http://www.gnu.org/licenses/>. */

#include "amz.h"
#include "amzPrivate.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>

#include <iostream>
#include <string.h>


namespace amz {

amz::amz()
    : m_pPrivate(new amzPrivate(this))
{
}

amz::~amz()
{
}

unsigned char * amz::decryptAmzData(const char * const pcEncryptedData, const int &iLen)
{
    // The keys used for decryption.
    const unsigned char ucKey[8] = {0x29, 0xAB, 0x9D, 0x18, 0xB2, 0x44, 0x9E, 0x31};
    const unsigned char ucInitV[8] = {0x5E, 0x72, 0xD7, 0x9A, 0x11, 0xB3, 0x4F, 0xEE};

    // Length of the decoded data.
    int iLenOut;

    // Decode the data.
    unsigned char *pucDecodedData = reinterpret_cast<unsigned char *>(m_pPrivate->decode64(
        pcEncryptedData, iLen, iLenOut));

    // We need a multiple length of 8 for decrypting the data. Look in DES_cbc_encrypt for more
    // details.
    iLenOut -= (iLenOut % 8);

    unsigned char * pucDecryptedData = m_pPrivate->decrypt(pucDecodedData, iLenOut, ucKey, ucInitV);

    // Delete the created pucDecodedData as we don't need it any longer.
    delete[] pucDecodedData;

    return pucDecryptedData;
}

char * amzPrivate::decode64(const char * const pcEncodedData, const int &iLenIn,  int &iLenOut)
{
    BIO *pBio64, *pMem;
    char *pcBuffer = new char[iLenIn + 1];
    char *pcEncodedDataTmp = new char[iLenIn + 1];

    memcpy(pcEncodedDataTmp, pcEncodedData, iLenIn + 1);

    // Limit for security reason.
    pcBuffer[iLenIn] = 0;

    // Create a new bio instance for base64 decoding.
    pBio64 = BIO_new(BIO_f_base64());

    // We don't have any newlines in the data.
    BIO_set_flags(pBio64, BIO_FLAGS_BASE64_NO_NL);

    pMem = BIO_new_mem_buf(pcEncodedDataTmp, iLenIn);
    pMem = BIO_push(pBio64, pMem);

    // Read the decoded data and set the len of it.
    iLenOut = BIO_read(pMem, pcBuffer, iLenIn);

    // Clean memory
    BIO_free_all(pMem);
    delete[] pcEncodedDataTmp;

    return pcBuffer;
}

unsigned char * amzPrivate::decrypt(unsigned char *pcData, const int &iLen, const unsigned char *pcKey,
    const unsigned char *pcIv)
{
    unsigned char *pcDecryptedData = new unsigned char[iLen];

    DES_key_schedule keysched;
    DES_key_schedule schedule;

    DES_set_key((C_Block *) pcKey, &keysched);

    /* Decryption occurs here */
    DES_cbc_encrypt(pcData, pcDecryptedData, iLen, &keysched, (C_Block *) pcIv, DES_DECRYPT);

    return pcDecryptedData;
}

}

