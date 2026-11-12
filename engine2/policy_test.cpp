#include "policy.hpp"
#include <cassert>
#include <cstdio>
#include <fstream>
int main(int argc,char** argv){
    if(argc!=2)return 2;
    {std::ofstream config(argv[1]);config<<"encryptkey==||==test-identity\n*cargo*==||==*\n/usr/local/*/zed==||==*\n*python*==||==*\n";}
    Policy policy(argv[1]);
    assert(!policy.trusted({"/usr/lib/cargo/bin/coreutils/head","head",false},"/Sample.java"));
    assert(!policy.trusted({"/opt/python-tools/unmatched-writer","unmatched-writer",false},"/Sample.java"));
    assert(policy.trusted({"/usr/bin/cargo","cargo",false},"/Sample.java"));
    assert(policy.trusted({"/usr/local/zed/zed","zed",false},"/Sample.java"));
    assert(!policy.trusted({"/tmp/zed","zed",false},"/Sample.java"));
    assert(policy.trusted({"/usr/bin/python3.14","python3.14",false},"/Sample.java"));
    std::remove(argv[1]);
}
