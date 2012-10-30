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


#ifndef AMZ_H
#define AMZ_H


namespace amz {

class amzPrivate;

class amz {
public:
    /**
     * Constructor */
    amz();

    /**
     * Destructor */
    ~amz();

    /**
     * Decrypt the amz data and return the decryption. The data will also be keeped in a member
     * variable for further actions.
     *
     * @param pcEncryptedData The encrypted data u want to decrypt.
     * @param iLen Length of the data.
     *
     * @return The decrypted data. NOTE: Delete if no longer use! */
    unsigned char * decryptAmzData(const char *pcEncryptedData, const int &iLen);

private:
    amzPrivate *m_pPrivate;
};

}


#endif // AMZ_H
