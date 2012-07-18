#ifndef SWAPBUFFERQUEUE_H
#define SWAPBUFFERQUEUE_H
#include <string>
#include <queue>
#include <vector>
#include <pthread.h>

using namespace std;

class SwapBufferQueue
{
    public:
        SwapBufferQueue();
        virtual ~SwapBufferQueue();
        void Add(string data);
        queue<string> DumpBuffer();
    protected:
    private:
    queue<string> bufferA;
    queue<string> bufferB;
    bool swap;
    pthread_mutex_t swapLock;
};

#endif // SWAPBUFFERQUEUE_H
