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

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
  string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

void PWSfile::GetSafesInDefaultLocations(vector<string> &files)
{
    vector<string> users;
    SystemUtils::GetFilesInDirectory("C:\\Users\\", users);
    for(vector<string>::iterator it = users.begin(); it < users.end(); it++)
    {
        vector<string> tfiles;
        string location("C:\\Users\\");
        location.append(*it);
        location.append("\\Documents\\My Safes\\");
        if(SystemUtils::GetFilesInDirectory(location.c_str(), tfiles) == 0 && tfiles.size() > 0)
        {
            for(vector<string>::iterator fit = tfiles.begin(); fit < tfiles.end(); fit++)
            {
                if(((*fit).rfind(".psafe3") != string::npos && (*fit).rfind(".psafe3") == (*fit).size() - 7))
                {
                    string file = location + *fit;
                    files.push_back(file);
                }
            }
        }
    }
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
                cout << dec << endl;
                cout << "hash: " << "$5$rounds=" << N << "$" << base64_encode(Salt, 32) << "$" << base64_encode(SHash, 32) << endl;
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
