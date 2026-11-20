#include "../../src/engine2/policy.hpp"
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
    assert(!encrypted.monitors_file("/src/File.java"));
    assert(!encrypted.encrypts_new_file("/src/File.java"));
    Policy empty(argv[1], nullptr, "");
    assert(!empty.monitors_file("/src/File.java"));
    assert(!empty.encrypts_new_file("/src/File.java"));
    assert(!encrypted.trusted({"/bin/new_file_mode","new_file_mode"},"/Sample.java"));
    Policy exclusions(argv[1], "/node_modules\n/另一个 目录", ".bin");
    assert(!exclusions.encrypts_new_file("/node_modules/esbuild/bin/esbuild.bin"));
    assert(!exclusions.encrypts_new_file("/另一个 目录/file.bin"));
    assert(exclusions.encrypts_new_file("/node_modules-old/file.bin"));
    assert(exclusions.encrypts_new_file("/nested/node_modules/file.bin"));
    assert(!policy.encrypts_new_file("/src/file"));
    Policy types(argv[1], "/node_modules", ".java\n.d.ts");
    assert(types.encrypts_new_file("/src/File.JAVA"));
    assert(types.encrypts_new_file("/src/Types.D.TS"));
    assert(!types.monitors_file("/node_modules/File.java"));
    assert(!types.encrypts_new_file("/node_modules/File.java"));
    assert(!types.monitors_file("/src.java/Binary"));
    assert(!types.monitors_file("/src/Types.ts"));
    assert(!types.monitors_file("/src/File.java.tmp"));
    Policy defaults(argv[1], "/custom", ".java\n.py", "node_modules\n__pycache__\ntarget");
    assert(defaults.encrypts_new_file("/src/File.java"));
    assert(!defaults.encrypts_new_file("/nested/node_modules/pkg/File.java"));
    assert(!defaults.encrypts_new_file("/nested/__pycache__/file.py"));
    assert(!defaults.encrypts_new_file("/custom/File.java"));
    assert(defaults.encrypts_new_file("/target-source/File.java"));
    assert(!defaults.monitors_file("/target/File.java"));
    assert(!defaults.monitors_file("/custom/File.java"));
    Policy excluded_root(argv[1], "/", ".java");
    assert(!excluded_root.monitors_file("/src/File.java"));
    std::remove(argv[1]);
}
