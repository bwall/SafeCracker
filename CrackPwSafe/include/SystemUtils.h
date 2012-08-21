#ifndef SYSTEMUTILS_H
#define SYSTEMUTILS_H

#include <sys/types.h>
#include <dirent.h>
#include <string>
#include <vector>

using namespace std;

class SystemUtils
{
    public:
        SystemUtils();
        virtual ~SystemUtils();
        static int GetFilesInDirectory(const char * dir, vector<string> &files);
    protected:
    private:
};

#endif // SYSTEMUTILS_H
