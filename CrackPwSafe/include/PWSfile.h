#ifndef PWSFILE_H
#define PWSFILE_H
#include "PassKey.h"
#include <string>
#include <stdio.h>
#include <iostream>
#include <iomanip>

using namespace std;

class PWSfile
{
    public:
        PWSfile();
        bool Load(string location);
        bool Load(string location, bool print);
        PassKey * GetPassKey();
        virtual ~PWSfile();
    protected:
    private:
        PassKey * passKey;
};

#endif // PWSFILE_H
