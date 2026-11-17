// Streaming 301 arithmetic only; no mount, policy, network or filesystem engine.
#include "cipher.hpp"
#include <cerrno>
#include <unistd.h>
int main(int argc,char**){
    if(argc!=1)return 2;
    try{
        Cipher301 cipher;unsigned char block[65536];uint64_t offset=1024;
        for(;;){
            auto count=read(STDIN_FILENO,block,sizeof(block));
            if(count<0&&errno==EINTR)continue;
            if(count<0)return 3;
            if(!count)return 0;
            cipher.apply(block,count,offset);offset+=count;
            ssize_t done=0;while(done<count){auto n=write(STDOUT_FILENO,block+done,count-done);if(n<0&&errno==EINTR)continue;if(n<=0)return 4;done+=n;}
        }
    }catch(...){return 5;}
}
