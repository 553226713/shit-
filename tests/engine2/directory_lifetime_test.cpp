// Model RELEASEDIR arriving synchronously with the readdir reply. The freed
// Directory and the next Handle share an allocator size class in production.
#define main engine_main
#include "../../src/engine2/main.cpp"
#undef main
#include <cassert>

static Directory *pending;
static Handle *replacement;
static const char *expected_path;

extern "C" const fuse_ctx *fuse_req_ctx(fuse_req_t) {
    static fuse_ctx context{};
    context.uid = getuid();
    context.gid = getgid();
    return &context;
}

extern "C" __attribute__((noinline)) int fuse_reply_buf(fuse_req_t, const char *, size_t) {
    assert(pending);
    // Destroy and reuse the same storage before the callback returns. Keep the
    // allocation itself alive so this test does not depend on malloc reuse.
    pending->~Directory();
    replacement = new (pending) Handle{};
    replacement->fd = -1;
    expected_path = replacement->path.data();
    return 0;
}

int main() {
    static_assert(sizeof(Directory) == sizeof(Handle));
    for (int i = 0; i < 1000; i++) {
        auto dir = opendir(".");
        assert(dir);
        pending = new Directory{dir, {}, {}};
        fuse_file_info info{};
        info.fh = reinterpret_cast<uint64_t>(pending);
        readdir(nullptr, 1, 4096, 0, &info);
        // Inspect the object representation: the old unlock writes four zero
        // bytes through a mutex pointer now aliasing this string's pointer.
        auto bytes = reinterpret_cast<volatile unsigned char *>(&replacement->path);
        uintptr_t observed = 0;
        for (size_t j = 0; j < sizeof(observed); j++)
            reinterpret_cast<unsigned char *>(&observed)[j] = bytes[j];
        assert(observed == reinterpret_cast<uintptr_t>(expected_path));
        replacement->path = std::string(100, 'p');
        assert(replacement->path == std::string(100, 'p'));
        replacement->~Handle();
        ::operator delete(pending);
    }
    puts("PASS: readdir reply permits immediate directory destruction and handle reuse");
}
