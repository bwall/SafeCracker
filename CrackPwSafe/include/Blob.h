#ifndef BLOB_H
#define BLOB_H
#include <string.h>

class Blob
{
    public:
        Blob(int size, char * data);
        Blob(const Blob& b);
        virtual ~Blob();
        int size;
        char * data;
    protected:
    private:
};

#endif // BLOB_H
