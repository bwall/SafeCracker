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
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, blob->data, blob->size);
    SHA256_Update(&sha256, salt, 32);
    SHA256_Final(output, &sha256);
    for (unsigned int i = 0; i < N; i++)
    {
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, output, 32);
        SHA256_Final(output, &sha256);
    }
}

void PassKey::StretchKey(const unsigned char *salt, const char * passkey, const int passlen, unsigned int N, unsigned char * output)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, passkey, passlen);
    SHA256_Update(&sha256, salt, 32);
    SHA256_Final(output, &sha256);
    for (unsigned int i = 0; i < N; i++)
    {
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, output, 32);
        SHA256_Final(output, &sha256);
    }
}
