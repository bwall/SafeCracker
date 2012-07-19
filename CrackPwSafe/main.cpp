#include <iostream>
#include <iomanip>
#include "include/PWSfile.h"
#include "include/PassKey.h"
#include <stdio.h>
#include <pthread.h>
#include <queue>
#include <sys/time.h>
#include "include/Blob.h"

#define ITERATION_REPORT 10000

using namespace std;

vector<pthread_t*> threads;
vector<queue<Blob>* > blobs;
vector<PassKey*> passkeys;
volatile bool done = false;
volatile bool started = false;
volatile bool found = false;
volatile unsigned long long iterationCount = 0;
struct timeval startTime;

void *crackThread(void *threadid)
{
    long index = (long)threadid;
    PassKey * pk = passkeys.at(index);
    queue<Blob>*  localQueue = blobs.at(index);
    while(!started) usleep(1000);
    gettimeofday(&startTime, NULL);
    while(!done && !found)
    {
        while(localQueue->size() > 0 && !found)
        {
            Blob * s = &localQueue->front();
            if(pk->CheckPassword(s))
            {
                cout << "Password is " << s->data << endl;
                flush(cout);
                done = true;
                found = true;
                localQueue->pop();
                return NULL;
            }
            iterationCount++;
            if(iterationCount % ITERATION_REPORT == 0)
            {
                struct timeval now;
                gettimeofday(&now, NULL);
                double seconds = (now.tv_sec + ((double)now.tv_usec / 1000000)) - (startTime.tv_sec + ((double)startTime.tv_usec / 1000000));
                cout << endl << dec << "Hashes(" << iterationCount << ") Per Second(" << seconds << "s): " << ((double)iterationCount)/(seconds);
            }
            localQueue->pop();
        }
    }
    return NULL;
}

int main(int argc, char ** argv)
{
    if(argc == 3)
    {
        string safelocation(argv[1]);
        string dictionarylocation(argv[2]);
        PWSfile file;
        if(!file.Load(safelocation, true))
        {
            cerr << "Failed to open safe." << endl;
            return 0;
        }
        PassKey * pk = file.GetPassKey();

        FILE * dict;
        if(dictionarylocation != "-")
        {
            dict = fopen(dictionarylocation.c_str(), "r");
        }
        else
        {
            dict = stdin;
        }
        if(dict == NULL)
        {
            cerr << "Failed to open dictionary file." << endl;
            return 0;
        }

        done = false;
        started = false;
        int thread_count = 4;
        for(long x = 0; x < thread_count; x++)
        {
            pthread_t * cThread = new pthread_t();
            threads.push_back(cThread);
            blobs.push_back(new queue<Blob>());
            passkeys.push_back(new PassKey(pk));
            pthread_create(cThread, NULL, crackThread, (void*)x);
        }

        char * password = new char[1024];
        unsigned long long loaded = 0;
        while (!feof(dict) && !done)
        {
            if (fgets(password, 1024, dict) != NULL)
            {
                if(strchr(password, 0x0d) != NULL) *(strchr(password, 0x0d)) = 0x00;
                else if(strchr(password, 0x0a) != NULL) *(strchr(password, 0x0a)) = 0x00;
                if(strlen(password) == 0)
                    continue;
                Blob p(strlen(password), password);
                int count = 0;
                for(int x = 0; x < thread_count; x++) count += (blobs.at(x))->size();
                while(count > 100000)
                {
                    usleep(10 * 1000);
                    count = 0;
                    for(int x = 0; x < thread_count; x++) count += (blobs.at(x))->size();
                }
                loaded++;
                (blobs.at(loaded % thread_count))->push(p);
                started = true;
            }
        }
        fclose(dict);
        int count = 0;
        for(int x = 0; x < thread_count; x++) count += (blobs.at(x))->size();
        while(count > 0 && !found)
        {
            usleep(100 * 1000);
            count = 0;
            for(int x = 0; x < thread_count; x++) count += (blobs.at(x))->size();
        }
        done = true;
        for(int x = 0; x < thread_count; x++)
        {
            pthread_join(*threads.at(x), NULL);
        }
        return 0;
    }
    else
    {
        //Print args
        cout << "Password Safe Cracker Arguments:" << endl << "safe-cracker <location of safe> <word file>" << endl;
    }
    return 0;
}
