#ifndef PWSFILE_H
#define PWSFILE_H
#include "AbstractSafe.h"
#include "SystemUtils.h"
#include "PassKey.h"
#include <string>
#include <stdio.h>
#include <iostream>
#include <iomanip>

using namespace std;

class PWSfile : AbstractSafe
{
    public:
        PWSfile();
        bool Load(string location);
        bool Load(string location, bool print);
        void GetSafesInDefaultLocations(vector<string> &files);
        PassKey * GetPassKey();
        virtual ~PWSfile();
    protected:
    private:
        PassKey * passKey;
};

#endif // PWSFILE_H
