#include "../include/Blob.h"

Blob::Blob(int size, char * data)
{
    //ctor
    this->data = new char[size + 1];
    memcpy(this->data, data, size + 1);
    this->size = size;
}

Blob::Blob(const Blob& b)
{
    this->data = new char[b.size + 1];
    memcpy(this->data, b.data, b.size + 1);
    this->size = b.size;
}

Blob::~Blob()
{
    //dtor
    delete[] data;
}
