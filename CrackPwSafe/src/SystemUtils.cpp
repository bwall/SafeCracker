#include "../include/SystemUtils.h"

SystemUtils::SystemUtils()
{
    //ctor
}

SystemUtils::~SystemUtils()
{
    //dtor
}

int SystemUtils::GetFilesInDirectory(const char * dir, vector<string> &files)
{
    DIR *dp;
    struct dirent *dirp;
    if((dp  = opendir(dir)) == NULL)
    {
        return errno;
    }

    while ((dirp = readdir(dp)) != NULL)
    {
        string file(dirp->d_name);
        if(file != "." && file != ".." && file != "desktop.ini")
        {
            files.push_back(file);
        }
    }
    closedir(dp);
    return 0;
}

