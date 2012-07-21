#ifndef SHA256_H
#define SHA256_H
#include <string.h>
#include <iostream>

using namespace std;

#define uint unsigned int
#define rotl(x,y) ( x<<y | x>>(32-y) )
#define rotr(x,y) ( x>>y | x<<(32-y) )
#define CHOICE(x,y,z) ( z ^ (x & ( y ^ z)) )
#define MAJORITY(x,y,z) ( (x & y) | (z & (x | y)) )
#define ROTXOR1(x) (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22))
#define ROTXOR2(x) (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25))
#define ROTXOR3(x) (rotr(x,7) ^ rotr(x,18) ^ (x>>3))
#define ROTXOR4(x) (rotr(x,17) ^ rotr(x,19) ^ (x>>10))
#define bytereverse(x) ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) )

class SHA256
{
    public:
        SHA256();
        void Update(unsigned char * buffer, int length);
        bool IterativeFinalize(unsigned char * input, unsigned int Iterations);
        void Finalize(unsigned char * output);
        virtual ~SHA256();
    protected:
    private:
        void sha256_transform(uint *state, uint *data);
		bool sha256_transform_i(uint Iterations, uint * desiredState);
        void sha256_block(const unsigned char * block);

        unsigned int state[8];
        unsigned int count_low, count_high;
        unsigned char block[64];
        unsigned int index;
};
#endif // SHA256_H
