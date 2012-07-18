#ifndef PASSKEY_H
#define PASSKEY_H
#include <openssl/sha.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include "Blob.h"

using namespace std;

class PassKey
{
    public:
        PassKey();
        PassKey(unsigned char * Salt, unsigned int N, unsigned char * stretchedKey);
        PassKey(PassKey * pk);
        bool CheckPassword(const Blob * b);
        bool CheckPassword(const char * password, int length);
        virtual ~PassKey();
    protected:
    private:
        unsigned char temp[32];
        unsigned char * Salt;
        unsigned int N;
        unsigned char * StretchedKey;
        static void StretchKey(const unsigned char * salt, const Blob * blob, const unsigned int N, unsigned char * output);
        static void StretchKey(const unsigned char * salt, const char * passkey, const int passlen, unsigned int N, unsigned char * output);
};

#endif // PASSKEY_H
