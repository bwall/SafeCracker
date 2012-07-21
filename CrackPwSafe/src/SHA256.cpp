#include "../include/SHA256.h"

static const unsigned int SHA256_K[64] = {  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                                0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                                0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                                0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static const unsigned int InitialState[8] = {0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL, 0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL};

SHA256::SHA256()
{
    //ctor
	//memcpy(state, InitialState, 32);
    state[0] = 0x6a09e667UL;
	state[1] = 0xbb67ae85UL;
	state[2] = 0x3c6ef372UL;
	state[3] = 0xa54ff53aUL;
	state[4] = 0x510e527fUL;
	state[5] = 0x9b05688cUL;
	state[6] = 0x1f83d9abUL;
	state[7] = 0x5be0cd19UL;
	count_low = count_high = 0;
	index = 0;
}

SHA256::~SHA256()
{
    //dtor
}

inline bool SHA256::sha256_transform_i(uint Iterations, uint * desiredState)
{
    uint word00,word01,word02,word03,word04,word05,word06,word07;
	uint word08,word09,word10,word11,word12,word13,word14,word15;
	uint temp0, temp1, temp2, temp3, temp4, temp5, temp6, temp7;

	for(uint counter = 0; counter < Iterations - 1; counter++)
	{
		temp0 = 0x6a09e667UL;
		temp1 = 0xbb67ae85UL;
		temp2 = 0x3c6ef372UL;
		temp3 = 0xa54ff53aUL;
		temp4 = 0x510e527fUL;
		temp5 = 0x9b05688cUL;
		temp6 = 0x1f83d9abUL;
		temp7 = 0x5be0cd19UL;

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x428a2f98 + ( (word00 = state[0]) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x71374491 + ( (word01 = state[1]) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb5c0fbcf + ( (word02 = state[2]) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xe9b5dba5 + ( (word03 = state[3]) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x3956c25b + ( (word04 = state[4]) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x59f111f1 + ( (word05 = state[5]) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x923f82a4 + ( (word06 = state[6]) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xab1c5ed5 + ( (word07 = state[7]) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xd807aa98 + ( (word08 = 0x80000000U) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x12835b01 + ( (word09 = 0) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x243185be + ( (word10 = 0) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x550c7dc3 + ( (word11 = 0) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x72be5d74 + ( (word12 = 0) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x80deb1fe + ( (word13 = 0) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x9bdc06a7 + ( (word14 = 0) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc19bf174 + ( (word15 = 256) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );



		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xe49b69c1 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xefbe4786 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x0fc19dc6 + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x240ca1cc + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x2de92c6f + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4a7484aa + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5cb0a9dc + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x76f988da + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x983e5152 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa831c66d + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb00327c8 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xbf597fc7 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xc6e00bf3 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd5a79147 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x06ca6351 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x14292967 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x27b70a85 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x2e1b2138 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x4d2c6dfc + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x53380d13 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x650a7354 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x766a0abb + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x81c2c92e + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x92722c85 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xa2bfe8a1 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa81a664b + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xc24b8b70 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xc76c51a3 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xd192e819 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd6990624 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xf40e3585 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x106aa070 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x19a4c116 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x1e376c08 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x2748774c + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x34b0bcb5 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x391c0cb3 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4ed8aa4a + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5b9cca4f + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x682e6ff3 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x748f82ee + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
		temp3 += temp7;
		temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

		temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x78a5636f + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
		temp2 += temp6;
		temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

		temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x84c87814 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
		temp1 += temp5;
		temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

		temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x8cc70208 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
		temp0 += temp4;
		temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

		temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x90befffa + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
		temp7 += temp3;
		temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

		temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xa4506ceb + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
		temp6 += temp2;
		temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

		temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xbef9a3f7 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
		temp5 += temp1;
		temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

		temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc67178f2 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
		temp4 += temp0;
		temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

		state[0] = 0x6a09e667UL + temp0;
		state[1] = 0xbb67ae85UL + temp1;
		state[2] = 0x3c6ef372UL + temp2;
		state[3] = 0xa54ff53aUL + temp3;
		state[4] = 0x510e527fUL + temp4;
		state[5] = 0x9b05688cUL + temp5;
		state[6] = 0x1f83d9abUL + temp6;
		state[7] = 0x5be0cd19UL + temp7;
	}
	temp0 = 0x6a09e667UL;
    temp1 = 0xbb67ae85UL;
    temp2 = 0x3c6ef372UL;
    temp3 = 0xa54ff53aUL;
    temp4 = 0x510e527fUL;
    temp5 = 0x9b05688cUL;
    temp6 = 0x1f83d9abUL;
    temp7 = 0x5be0cd19UL;

    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x428a2f98 + ( (word00 = state[0]) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x71374491 + ( (word01 = state[1]) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb5c0fbcf + ( (word02 = state[2]) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xe9b5dba5 + ( (word03 = state[3]) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x3956c25b + ( (word04 = state[4]) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x59f111f1 + ( (word05 = state[5]) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x923f82a4 + ( (word06 = state[6]) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xab1c5ed5 + ( (word07 = state[7]) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xd807aa98 + ( (word08 = 0x80000000U) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x12835b01 + ( (word09 = 0) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x243185be + ( (word10 = 0) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x550c7dc3 + ( (word11 = 0) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x72be5d74 + ( (word12 = 0) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x80deb1fe + ( (word13 = 0) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x9bdc06a7 + ( (word14 = 0) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc19bf174 + ( (word15 = 256) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );



    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xe49b69c1 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xefbe4786 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x0fc19dc6 + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x240ca1cc + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x2de92c6f + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4a7484aa + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5cb0a9dc + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x76f988da + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x983e5152 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa831c66d + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xb00327c8 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xbf597fc7 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xc6e00bf3 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd5a79147 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x06ca6351 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x14292967 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x27b70a85 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x2e1b2138 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x4d2c6dfc + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x53380d13 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x650a7354 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x766a0abb + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x81c2c92e + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x92722c85 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0xa2bfe8a1 + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0xa81a664b + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0xc24b8b70 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0xc76c51a3 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0xd192e819 + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xd6990624 + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xf40e3585 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x106aa070 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x19a4c116 + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x1e376c08 + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x2748774c + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x34b0bcb5 + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x391c0cb3 + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
    temp7 += temp3;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0x4ed8aa4a + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
    temp6 += temp2;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0x5b9cca4f + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
    temp5 += temp1;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0x682e6ff3 + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
    temp4 += temp0;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

    temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + 0x748f82ee + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
    temp3 += temp7;
    temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

    temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + 0x78a5636f + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
    temp2 += temp6;
    temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

    temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + 0x84c87814 + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
    temp1 += temp5;
    temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

    temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + 0x8cc70208 + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
    temp0 += temp4;
    temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

    temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + 0x90befffa + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
    temp7 += temp3;
    if(temp7 != desiredState[7])
        return false;
    temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );
    if(temp3 != desiredState[3])
        return false;

    temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + 0xa4506ceb + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
    temp6 += temp2;
    if(temp6 != desiredState[6])
        return false;
    temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );
    if(temp2 != desiredState[2])
        return false;

    temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + 0xbef9a3f7 + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
    temp5 += temp1;
    if(temp5 != desiredState[5])
        return false;
    temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );
    if(temp1 != desiredState[1])
        return false;


    temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + 0xc67178f2 + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
    temp4 += temp0;
    if(temp4 != desiredState[4])
        return false;
    temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );
    if(temp0 != desiredState[0])
        return false;

    return true;
}

inline void SHA256::sha256_transform(uint *state, uint * data)
{
    uint word00,word01,word02,word03,word04,word05,word06,word07;
	uint word08,word09,word10,word11,word12,word13,word14,word15;
	uint temp0,temp1,temp2,temp3,temp4,temp5,temp6,temp7;

	temp0 = state[0]; temp1 = state[1];
	temp2 = state[2]; temp3 = state[3];
	temp4 = state[4]; temp5 = state[5];
	temp6 = state[6]; temp7 = state[7];

	//First Iteration
	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[0] + ( (word00 = data[0]) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[1] + ( (word01 = data[1]) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[2] + ( (word02 = data[2]) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[3] + ( (word03 = data[3]) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[4] + ( (word04 = data[4]) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[5] + ( (word05 = data[5]) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[6] + ( (word06 = data[6]) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[7] + ( (word07 = data[7]) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[8] + ( (word08 = data[8]) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[9] + ( (word09 = data[9]) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[10] + ( (word10 = data[10]) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[11] + ( (word11 = data[11]) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[12] + ( (word12 = data[12]) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[13] + ( (word13 = data[13]) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[14] + ( (word14 = data[14]) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[15] + ( (word15 = data[15]) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );



	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[16] + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[17] + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[18] + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[19] + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[20] + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[21] + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[22] + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[23] + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[24] + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[25] + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[26] + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[27] + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[28] + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[29] + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[30] + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[31] + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[32] + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[33] + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[34] + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[35] + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[36] + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[37] + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[38] + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[39] + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[40] + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[41] + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[42] + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[43] + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[44] + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[45] + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[46] + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[47] + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );




	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[48] + ( (word00 += ROTXOR4( word14 ) + word09 + ROTXOR3( word01 ) ) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[49] + ( (word01 += ROTXOR4( word15 ) + word10 + ROTXOR3( word02 ) ) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[50] + ( (word02 += ROTXOR4( word00 ) + word11 + ROTXOR3( word03 ) ) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[51] + ( (word03 += ROTXOR4( word01 ) + word12 + ROTXOR3( word04 ) ) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[52] + ( (word04 += ROTXOR4( word02 ) + word13 + ROTXOR3( word05 ) ) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[53] + ( (word05 += ROTXOR4( word03 ) + word14 + ROTXOR3( word06 ) ) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[54] + ( (word06 += ROTXOR4( word04 ) + word15 + ROTXOR3( word07 ) ) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[55] + ( (word07 += ROTXOR4( word05 ) + word00 + ROTXOR3( word08 ) ) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

	temp7 += ROTXOR2( temp4 ) + CHOICE( temp4, temp5, temp6 ) + SHA256_K[56] + ( (word08 += ROTXOR4( word06 ) + word01 + ROTXOR3( word09 ) ) );
	temp3 += temp7;
	temp7 += ROTXOR1( temp0 ) + MAJORITY( temp0, temp1, temp2 );

	temp6 += ROTXOR2( temp3 ) + CHOICE( temp3, temp4, temp5 ) + SHA256_K[57] + ( (word09 += ROTXOR4( word07 ) + word02 + ROTXOR3( word10 ) ) );
	temp2 += temp6;
	temp6 += ROTXOR1( temp7 ) + MAJORITY( temp7, temp0, temp1 );

	temp5 += ROTXOR2( temp2 ) + CHOICE( temp2, temp3, temp4 ) + SHA256_K[58] + ( (word10 += ROTXOR4( word08 ) + word03 + ROTXOR3( word11 ) ) );
	temp1 += temp5;
	temp5 += ROTXOR1( temp6 ) + MAJORITY( temp6, temp7, temp0 );

	temp4 += ROTXOR2( temp1 ) + CHOICE( temp1, temp2, temp3 ) + SHA256_K[59] + ( (word11 += ROTXOR4( word09 ) + word04 + ROTXOR3( word12 ) ) );
	temp0 += temp4;
	temp4 += ROTXOR1( temp5 ) + MAJORITY( temp5, temp6, temp7 );

	temp3 += ROTXOR2( temp0 ) + CHOICE( temp0, temp1, temp2 ) + SHA256_K[60] + ( (word12 += ROTXOR4( word10 ) + word05 + ROTXOR3( word13 ) ) );
	temp7 += temp3;
	temp3 += ROTXOR1( temp4 ) + MAJORITY( temp4, temp5, temp6 );

	temp2 += ROTXOR2( temp7 ) + CHOICE( temp7, temp0, temp1 ) + SHA256_K[61] + ( (word13 += ROTXOR4( word11 ) + word06 + ROTXOR3( word14 ) ) );
	temp6 += temp2;
	temp2 += ROTXOR1( temp3 ) + MAJORITY( temp3, temp4, temp5 );

	temp1 += ROTXOR2( temp6 ) + CHOICE( temp6, temp7, temp0 ) + SHA256_K[62] + ( (word14 += ROTXOR4( word12 ) + word07 + ROTXOR3( word15 ) ) );
	temp5 += temp1;
	temp1 += ROTXOR1( temp2 ) + MAJORITY( temp2, temp3, temp4 );

	temp0 += ROTXOR2( temp5 ) + CHOICE( temp5, temp6, temp7 ) + SHA256_K[63] + ( (word15 += ROTXOR4( word13 ) + word08 + ROTXOR3( word00 ) ) );
	temp4 += temp0;
	temp0 += ROTXOR1( temp1 ) + MAJORITY( temp1, temp2, temp3 );

	state[0] += temp0;
	state[1] += temp1;
	state[2] += temp2;
	state[3] += temp3;
	state[4] += temp4;
	state[5] += temp5;
	state[6] += temp6;
	state[7] += temp7;
}

void SHA256::sha256_block(const unsigned char * block)
{
    uint data[16];
	if (!++count_low)
		++count_high;

	for (int i = 0; i < 16; i++, block += 4)
	{
	    data[i] = (*(block) << 24) | (*(block + 1) << 16) | (*(block + 2) << 8) | (*(block + 3));
	}

	sha256_transform(state, data);
}

void SHA256::Update(unsigned char * buffer, int length)
{
    if (index)
	{
		unsigned left = 64 - index;
		if (length < left)
		{
			memcpy(block + index, buffer, length);
			index += length;
			return;
		}
		else
		{
			memcpy(block + index, buffer, left);
			sha256_block(buffer);
			buffer += left;
			length -= left;
		}
	}
	while (length >= 64)
	{
		sha256_block(buffer);
		buffer += 64;
		length -= 64;
	}
	memcpy(block, buffer, length);
	index = length;
}

bool SHA256::IterativeFinalize(unsigned char * input, unsigned int Iterations)
{
	uint data[16];
	int i;
	int words;

	i = index;

	block[i++] = 0x80;

	for (; i & 3; i++) block[i] = 0;

	words = i >> 2;
	for (i = 0; i < words; i++)
	{
	    data[i] = (*((block + 4 * i)) << 24) | (*((block + 4 * i) + 1) << 16) | (*((block + 4 * i) + 2) << 8) | (*((block + 4 * i) + 3));
	}

	if (words > (16 - 2))
	{
		for (i = words; i < 16; i++) data[i] = 0;
		sha256_transform(state, data);
		for (i = 0; i < (16 - 2); i++) data[i] = 0;
	}
	else
	{
		for (i = words; i < 16 - 2; i++) data[i] = 0;
	}

	data[14] = (count_high << 9) | (count_low >> 23);
	data[15] = (count_low << 9) | (index << 3);
	sha256_transform(state, data);
	unsigned int desiredState[8];
    for (int i = 0; i < 8; i++)
    {
        desiredState[i] = (*((input + 4 * i)) << 24) | (*((input + 4 * i) + 1) << 16) | (*((input + 4 * i) + 2) << 8) | (*((input + 4 * i) + 3));
    }
    desiredState[0] -= 0x6a09e667UL;
    desiredState[1] -= 0xbb67ae85UL;
    desiredState[2] -= 0x3c6ef372UL;
    desiredState[3] -= 0xa54ff53aUL;
    desiredState[4] -= 0x510e527fUL;
    desiredState[5] -= 0x9b05688cUL;
    desiredState[6] -= 0x1f83d9abUL;
    desiredState[7] -= 0x5be0cd19UL;
    return sha256_transform_i(Iterations, desiredState);
}

void SHA256::Finalize(unsigned char * output)
{
	uint data[16];
	int i;
	int words;

	i = index;

	block[i++] = 0x80;

	for (; i & 3; i++) block[i] = 0;

	words = i >> 2;
	for (i = 0; i < words; i++)
	{
	    data[i] = (*((block + 4 * i)) << 24) | (*((block + 4 * i) + 1) << 16) | (*((block + 4 * i) + 2) << 8) | (*((block + 4 * i) + 3));
	}

	if (words > (16 - 2))
	{
		for (i = words; i < 16; i++) data[i] = 0;
		sha256_transform(state, data);
		for (i = 0; i < (16 - 2); i++) data[i] = 0;
	}
	else
	{
		for (i = words; i < 16 - 2; i++) data[i] = 0;
	}

	data[16 - 2] = (count_high << 9) | (count_low >> 23);
	data[16 - 1] = (count_low << 9) | (index << 3);
	sha256_transform(state, data);
    for (int i = 0; i < 8; i++)
    {
        *output++ = state[i] >> 24;
        *output++ = 0xff & (state[i] >> 16);
        *output++ = 0xff & (state[i] >> 8);
        *output++ = 0xff & state[i];
    }
}
