#include "../include/PassKey.h"

PassKey::PassKey()
{
    //ctor
}

PassKey::PassKey(PassKey * pk)
{
    this->Salt = new unsigned char[32];
    memcpy(this->Salt, pk->Salt, 32);
    this->N = pk->N;
    this->StretchedKey = new unsigned char[32];
    memcpy(this->StretchedKey, pk->StretchedKey, 32);
}

PassKey::~PassKey()
{
    //dtor
}

PassKey::PassKey(unsigned char * Salt, unsigned int N, unsigned char * stretchedKey)
{
    this->Salt = Salt;
    this->N = N;
    this->StretchedKey = stretchedKey;
}

bool PassKey::CheckPassword(const Blob * b)
{
    StretchKey(this->Salt, b, this->N + 1, temp);
    return (memcmp(temp, this->StretchedKey, 32) == 0);
}

bool PassKey::CheckPassword(const char * password, int length)
{
    StretchKey(this->Salt, password, length, this->N + 1, temp);
    return (memcmp(temp, this->StretchedKey, 32) == 0);
}

void PassKey::StretchKey(const unsigned char * salt, const Blob * blob, const unsigned int N, unsigned char * output)
{
    SHA256 sha;
    sha.Update((unsigned char*)blob->data, blob->size);
    sha.Update((unsigned char*)salt, 32);
    sha.IterativeFinalize(output, N);
}

void PassKey::StretchKey(const unsigned char *salt, const char * passkey, const int passlen, unsigned int N, unsigned char * output)
{
    SHA256 sha;
    sha.Update((unsigned char*)passkey, passlen);
    sha.Update((unsigned char*)salt, 32);
    sha.IterativeFinalize(output, N);
}
