// Bridge the pinned native client's authenticated, read-only policy queries.
#define _GLIBCXX_USE_CXX11_ABI 0
#include <cstdio>
#include <list>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <sys/stat.h>

using Cells = std::list<std::string>;
using Search = bool (*)(void *, std::string, Cells *, long *, long *, int);
static constexpr auto search_address = 0x467654UL;
static void quote(FILE *out, const std::string &value) {
    fputc('"', out);
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { fputc('\\', out); fputc(c, out); }
        else if (c < 32) fprintf(out, "\\u%04x", c);
        else fputc(c, out);
    }
    fputc('"', out);
}
static bool query(FILE *out, const std::string &sql, long expected) {
    Cells cells;
    long cols = 0, rows = 0;
    auto search = reinterpret_cast<Search>(search_address);
    bool ok = search(reinterpret_cast<void *>(0x5064a0), sql, &cells, &cols, &rows, 3);
    if (!ok || (rows && cols != expected) || rows * cols != static_cast<long>(cells.size())) return false;
    fputc('[', out);
    long index = 0;
    for (const auto &cell : cells) {
        if (index) fputc(',', out);
        quote(out, cell);
        ++index;
    }
    fputc(']', out);
    return true;
}
static void *collect(void *) {
    auto online = reinterpret_cast<volatile int *>(0x50645c);
    for (int i = 0; i < 100 && !*online; ++i) usleep(100000);
    if (!*online) return nullptr;
    // Login performs its own DB reads on this object before becoming idle.
    sleep(1);
    const char *temporary = "windows-policy.json.tmp";
    FILE *out = fopen(temporary, "w");
    if (!out) return nullptr;
    fchmod(fileno(out), 0600);
    fputs("{\"assigned\":", out);
    int device = *reinterpret_cast<int *>(0x500c5c);
    bool ok = query(out,
        "select PolicyID from a_equippolicymap where PolicyName='p_fileencrypt_policy' and MtID="
        + std::to_string(device), 1);
    fputs(",\"applications\":", out);
    ok = query(out,
        "select c.PolicyID,n.Name,c.Name1,coalesce(b.ProcessName,'') "
        "from a_policycontent c join a_policyname n on n.ID=c.PolicyID "
        "left join b_encryptpolicy b on lower(b.CodeName)=lower(c.Name1) "
        "where c.Code='FILEENCRYPT_PATH' order by c.PolicyID,c.ID", 4) && ok;
    fputs(",\"encryption_keys\":", out);
    ok = query(out, "select Name1 from g_systemset where Code='FileEncryptKey' order by ID", 1) && ok;
    fputs(ok ? ",\"ok\":true}\n" : ",\"ok\":false}\n", out);
    fclose(out);
    rename(temporary, "windows-policy.json");
    return nullptr;
}
__attribute__((constructor)) static void start() {
    char executable[1024] = {};
    if (readlink("/proc/self/exe", executable, sizeof(executable)-1) < 0) return;
    std::string path(executable);
    if (path.size() < 8 || path.substr(path.size()-8) != "/svchost") return;
    pthread_t thread;
    if (!pthread_create(&thread, nullptr, collect, nullptr)) pthread_detach(thread);
}
