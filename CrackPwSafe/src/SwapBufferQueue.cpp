#include "../include/SwapBufferQueue.h"

SwapBufferQueue::SwapBufferQueue()
{
    //ctor
    this->swap = false;
    this->swapLock = PTHREAD_MUTEX_INITIALIZER;
}

SwapBufferQueue::~SwapBufferQueue()
{
    //dtor
}

void SwapBufferQueue::Add(string data)
{
    pthread_mutex_lock(&this->swapLock);
    if(swap)
    {
        bufferB.push(data);
    }
    else
    {
        bufferA.push(data);
    }
    pthread_mutex_unlock(&this->swapLock);
}

queue<string> SwapBufferQueue::DumpBuffer()
{
    queue<string> ret;
    pthread_mutex_lock(&this->swapLock);
    swap = !swap;
    pthread_mutex_unlock(&this->swapLock);
    if(swap)
    {
        while(!bufferA.empty())
        {
            ret.push(bufferA.front());
            bufferA.pop();
        }
    }
    else
    {
        while(!bufferB.empty())
        {
            ret.push(bufferB.front());
            bufferB.pop();
        }
    }
    return ret;
}
