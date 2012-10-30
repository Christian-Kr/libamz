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

#ifndef AMZPRIVATE_H
#define AMZPRIVATE_H

#include <string>


namespace amz {

class amzPrivate {
public:
    /**
     * Constructor */
    amzPrivate(amz *pPublic) : m_pPublic(pPublic) {};

    /**
     * Decode the given string.
     *
     * @param pcData The data for decoding.
     * @param iLenIn The length of the data.
     * @param iLenOut The output length. NOTE: This variable will be set in this function.
     *
     * @return The decoded string. NOTE: Delete if no longer use! */
    char * decode64(const char * const pcData, const int &iLenIn, int &iLenOut);

    unsigned char * decrypt(unsigned char *pcData, const int &iLen, const unsigned char *pcKey,
        const unsigned char *pcIv);

    amz *m_pPublic;
    std::wstring *m_decryptedData;
    char **m_encryptedData;
};

}


#endif // AMZPRIVATE_H
