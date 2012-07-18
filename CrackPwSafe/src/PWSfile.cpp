#include "../include/PWSfile.h"

PWSfile::PWSfile()
{
    //ctor
}

PWSfile::~PWSfile()
{
    //dtor
}

bool PWSfile::Load(string location)
{
    return this->Load(location, false);
}

bool PWSfile::Load(string location, bool print)
{
    FILE * f = fopen(location.c_str(), "rb");
    bool status = false;
    if(f != NULL)
    {
        //Check for expected format
        if(fgetc(f) == 'P' && fgetc(f) == 'W' && fgetc(f) == 'S' && fgetc(f) == '3')
        {
            unsigned char * Salt = new unsigned char[32];
            fread(Salt, 1, 32, f);
            unsigned int N = 0;
            fread(&N, 1, 4, f);
            unsigned char * SHash = new unsigned char[32];
            fread(SHash, 1, 32, f);
            if(print)
            {
                cout << "Salt: ";
                for(int i = 0; i < 32; i++)
                {
                    cout << hex << setw(2) << setfill('0') << (int)Salt[i];
                }
                cout << endl << "Iterations: " << dec << N << endl << "Stored Hash: ";
                for(int i = 0; i < 32; i++)
                {
                    cout << hex << setw(2) << setfill('0') << (int)SHash[i];
                }
                cout << endl;
                flush(cout);
            }
            passKey = new PassKey(Salt, N, SHash);
            status = true;
        }
        fclose(f);
    }
    return status;
}

PassKey* PWSfile::GetPassKey()
{
    return this->passKey;
}
