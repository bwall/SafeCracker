#ifndef ABSTRACTSAFE_H
#define ABSTRACTSAFE_H

#include <vector>
#include <string>

using namespace std;

class AbstractSafe
{
    public:
        AbstractSafe();
        virtual ~AbstractSafe();
        virtual void GetSafesInDefaultLocations(vector<string> &files) = 0;
        virtual bool Load(string location) = 0;
    protected:
    private:
};

#endif // ABSTRACTSAFE_H
