/* Unmatched executable: inspect the raw view even while an editor has mmap. */
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    int fd=open(argv[1],O_RDONLY);struct stat st;
    if(fd<0||fstat(fd,&st)){perror("open/stat");return 3;}
    if(!st.st_size){close(fd);return 0;}
    const char* p=mmap(0,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(p==MAP_FAILED){perror("mmap");return 4;}
    size_t done=0;
    while(done<(size_t)st.st_size){ssize_t n=write(1,p+done,st.st_size-done);if(n<=0)return 5;done+=n;}
    munmap((void*)p,st.st_size);close(fd);return 0;
}
