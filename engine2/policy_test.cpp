#include "policy.hpp"
#include <cassert>
#include <cstdio>
#include <fstream>
int main(int argc,char** argv){
    if(argc!=2)return 2;
    {std::ofstream config(argv[1]);config<<"encryptkey==||==test-identity\n*cargo*==||==*\n/usr/local/*/zed==||==*\n*python*==||==*\n";}
    Policy policy(argv[1]);
    assert(!policy.encrypt_new);
    assert(!policy.trusted({"/usr/lib/cargo/bin/coreutils/head","head"},"/Sample.java"));
    assert(!policy.trusted({"/opt/python-tools/unmatched-writer","unmatched-writer"},"/Sample.java"));
    assert(policy.trusted({"/usr/bin/cargo","cargo"},"/Sample.java"));
    assert(policy.trusted({"/usr/local/zed/zed","zed"},"/Sample.java"));
    assert(!policy.trusted({"/tmp/zed","zed"},"/Sample.java"));
    assert(policy.trusted({"/usr/bin/python3.14","python3.14"},"/Sample.java"));
    {std::ofstream config(argv[1]);config<<"encryptkey==||==test-identity\nnew_file_mode==||==encrypted\n";}
    Policy encrypted(argv[1]);
    assert(encrypted.encrypt_new);
    assert(!encrypted.trusted({"/bin/new_file_mode","new_file_mode"},"/Sample.java"));
    std::remove(argv[1]);
}
