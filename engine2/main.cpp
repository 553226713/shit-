#define FUSE_USE_VERSION 318
#include "cipher.hpp"
#include "policy.hpp"
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <dirent.h>
#include <fuse_lowlevel.h>
#include <grp.h>
#include <limits>
#include <linux/fuse.h>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <signal.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <thread>
#include <tuple>
#include <vector>

// This engine is deliberately independent of the production launcher. Only the
// mount broker owns CAP_SYS_ADMIN; backing filesystem access uses request fsuid.
struct Cred {
    uid_t uid;
    gid_t gid;
    explicit Cred(fuse_req_t r) {
        auto c = fuse_req_ctx(r);
        gid = setfsgid(c->gid);
        uid = setfsuid(c->uid);
    }
    ~Cred() {
        setfsuid(uid);
        setfsgid(gid);
    }
};
struct Storage {
    std::shared_mutex data;
    std::mutex cache;
    struct stat stamp{};
    bool classified = false;
    int state = 0;
    int backing = 0;
    bool backing_write = false;
    unsigned passthrough_refs = 0;
};
struct Node {
    int fd;
    fuse_ino_t ino;
    uint64_t refs = 0;
    std::string path;
    bool gc_queued = false;
    int view = 0; // 0 ordinary, 1 decoded, 2 ciphertext: separate kernel caches.
    std::shared_ptr<Storage> storage;
    Node(int f, fuse_ino_t i, std::string p) : fd(f), ino(i), path(std::move(p)) {}
    ~Node() { close(fd); }
};
struct Handle {
    int fd;
    std::shared_ptr<Node> node;
    bool passthrough = false, authorized = false, raw = false, append = false;
    ~Handle() { close(fd); }
};
struct Directory {
    DIR *stream;
    std::shared_ptr<Node> node;
    std::mutex lock;
    ~Directory() { closedir(stream); }
};
struct Counters {
    std::atomic<uint64_t> lookup{}, getattr{}, opens{}, passthrough{}, reads{}, writes{},
        cipher_reads{}, cipher_writes{}, header_probes{};
};
struct Engine {
    Policy policy;
    Cipher301 cipher;
    std::mutex nodes_lock;
    std::map<fuse_ino_t, std::shared_ptr<Node>> nodes;
    std::map<std::tuple<dev_t, ino_t, int>, fuse_ino_t> identity;
    std::deque<fuse_ino_t> garbage;
    fuse_ino_t next = 2;
    bool passthrough = false, mmap = false;
    Counters stats;
    uid_t owner = 0;
    explicit Engine(const char *root, const char *config) : policy(config) {
        int fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0)
            throw std::runtime_error("backing directory cannot be opened");
        struct stat root_stat{};
        if (fstat(fd, &root_stat))
            throw std::runtime_error("backing stat failed");
        owner = root_stat.st_uid;
        auto n = std::make_shared<Node>(fd, 1, "");
        n->storage = std::make_shared<Storage>();
        n->refs = 1;
        nodes[1] = n;
    }
    std::shared_ptr<Node> get(fuse_ino_t ino) {
        std::lock_guard g(nodes_lock);
        auto it = nodes.find(ino);
        return it == nodes.end() ? nullptr : it->second;
    }
    std::string path(const std::shared_ptr<Node> &n) {
        std::lock_guard g(nodes_lock);
        return n->path;
    }
    std::shared_ptr<Storage> storage(const struct stat &st) {
        std::lock_guard g(nodes_lock);
        for (int view = 0; view < 3; view++) {
            auto it = identity.find({st.st_dev, st.st_ino, view});
            if (it != identity.end())
                return nodes.at(it->second)->storage;
        }
        return std::make_shared<Storage>();
    }
    std::shared_ptr<Node> add(std::shared_ptr<Node> candidate, const struct stat &st) {
        std::lock_guard g(nodes_lock);
        sweep();
        auto key = std::make_tuple(st.st_dev, st.st_ino, candidate->view);
        auto it = identity.find(key);
        if (it != identity.end()) {
            auto n = nodes.at(it->second);
            n->refs++;
            return n;
        }
        // Another view may have arrived while the header was being inspected.
        for (int view = 0; view < 3; view++) {
            auto existing = identity.find({st.st_dev, st.st_ino, view});
            if (existing != identity.end()) {
                candidate->storage = nodes.at(existing->second)->storage;
                break;
            }
        }
        candidate->ino = next++;
        candidate->refs = 1;
        identity[key] = candidate->ino;
        nodes[candidate->ino] = candidate;
        return candidate;
    }
    void collect(const std::shared_ptr<Node> &n) {
        if (n->ino == 1 || n->refs)
            return;
        if (n.use_count() > 2) {
            if (!n->gc_queued) {
                n->gc_queued = true;
                garbage.push_back(n->ino);
            }
            return;
        }
        struct stat st{};
        if (!fstat(n->fd, &st))
            identity.erase({st.st_dev, st.st_ino, n->view});
        nodes.erase(n->ino);
    }
    void sweep() {
        auto count = std::min<size_t>(16, garbage.size());
        while (count--) {
            auto ino = garbage.front();
            garbage.pop_front();
            auto it = nodes.find(ino);
            if (it == nodes.end())
                continue;
            auto n = it->second;
            n->gc_queued = false;
            collect(n);
        }
    }
    void forget(fuse_ino_t ino, uint64_t count) {
        if (ino == 1)
            return;
        std::lock_guard g(nodes_lock);
        sweep();
        auto it = nodes.find(ino);
        if (it == nodes.end())
            return;
        auto n = it->second;
        n->refs = n->refs > count ? n->refs - count : 0;
        collect(n);
    }
    void collect(fuse_ino_t ino) {
        std::lock_guard g(nodes_lock);
        sweep();
        auto it = nodes.find(ino);
        if (it != nodes.end()) {
            auto n = it->second;
            collect(n);
        }
    }
    static std::string proc(int fd) { return "/proc/self/fd/" + std::to_string(fd); }
    int reopen(const std::shared_ptr<Node> &n, int flags) {
        return ::open(proc(n->fd).c_str(), flags | O_CLOEXEC);
    }
    int classify(const std::shared_ptr<Node> &n, const struct stat &st, int fd = -1) {
        if (!S_ISREG(st.st_mode) || st.st_size < 32 || !policy.scoped(path(n)))
            return 0;
        std::lock_guard g(n->storage->cache);
        auto &a = n->storage->stamp;
        if (n->storage->classified && a.st_size == st.st_size &&
            a.st_mtim.tv_sec == st.st_mtim.tv_sec && a.st_mtim.tv_nsec == st.st_mtim.tv_nsec &&
            a.st_ctim.tv_sec == st.st_ctim.tv_sec && a.st_ctim.tv_nsec == st.st_ctim.tv_nsec)
            return n->storage->state;
        bool owned = fd < 0 || (fcntl(fd, F_GETFL) & O_ACCMODE) == O_WRONLY;
        if (owned) {
            fd = reopen(n, O_RDONLY);
            if (fd < 0 && errno == EACCES) {
                // Signature-only privilege: ordinary write-only files must keep
                // working, while unreadable ciphertext must never be mistaken
                // for plaintext and silently truncated. Actual opens still use
                // request credentials and kernel default_permissions.
                auto previous = setfsuid(0);
                fd = reopen(n, O_RDONLY);
                int error = errno;
                setfsuid(previous);
                errno = error;
            }
        }
        if (fd < 0)
            return -errno;
        std::array<unsigned char, 1024> header{};
        stats.header_probes++;
        int state = header_state(fd, header, policy);
        if (owned)
            close(fd);
        // Transient read/permission failures must never become a persistent class.
        if (state >= 0 || state == -EACCES || state == -EOPNOTSUPP) {
            n->storage->stamp = st;
            n->storage->state = state;
            n->storage->classified = true;
        }
        return state;
    }
    void invalidate(const std::shared_ptr<Node> &n) {
        std::lock_guard g(n->storage->cache);
        n->storage->classified = false;
    }
    bool decoded(fuse_req_t req, const std::shared_ptr<Node> &n) {
        auto id = policy.identity(fuse_req_ctx(req)->pid);
        return !id.raw && policy.trusted(id, path(n));
    }
    int attributes(fuse_req_t req, const std::shared_ptr<Node> &n, struct stat &st,
                   int *state = nullptr) {
        if (fstat(n->fd, &st))
            return errno;
        int enc = classify(n, st);
        if (state)
            *state = enc;
        if (enc == 1 && n->view == 1)
            st.st_size = std::max<off_t>(0, st.st_size - 1024);
        return 0;
    }
    int entry(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_entry_param &entry) {
        auto dir = get(parent);
        if (!dir)
            return ESTALE;
        int fd = openat(dir->fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            return errno;
        struct stat st{};
        if (fstat(fd, &st)) {
            int error = errno;
            close(fd);
            return error;
        }
        auto candidate = std::make_shared<Node>(fd, 0, path(dir) + "/" + name);
        candidate->storage = storage(st);
        int enc = classify(candidate, st);
        candidate->view = enc ? (decoded(req, candidate) ? 1 : 2) : 0;
        auto n = add(candidate, st);
        entry = {};
        entry.ino = n->ino;
        entry.generation = 1;
        int error = attributes(req, n, entry.attr);
        if (error) {
            forget(n->ino, 1);
            return error;
        }
        // Regular dentries revalidate so a rename or Git checkout can change
        // encryption state/view without reusing another view's kernel cache.
        entry.entry_timeout = S_ISREG(st.st_mode) ? 0 : 1;
        entry.attr_timeout = enc == 0 ? 1 : 0;
        return 0;
    }
    std::string metrics_json() {
        std::lock_guard g(nodes_lock);
        char result[1024];
        snprintf(
            result, sizeof(result),
            "{\"passthrough_enabled\":%s,\"mmap_enabled\":%s,\"lookup\":%lu,\"getattr\":%lu,"
            "\"opens\":%lu,\"passthrough_opens\":%lu,\"read_callbacks\":%lu,\"write_callbacks\":%"
            "lu,"
            "\"cipher_reads\":%lu,\"cipher_writes\":%lu,\"header_probes\":%lu,\"live_nodes\":%zu}",
            passthrough ? "true" : "false", mmap ? "true" : "false", stats.lookup.load(),
            stats.getattr.load(), stats.opens.load(), stats.passthrough.load(), stats.reads.load(),
            stats.writes.load(), stats.cipher_reads.load(), stats.cipher_writes.load(),
            stats.header_probes.load(), nodes.size());
        return result;
    }
    void metrics(const char *file) {
        if (!file)
            return;
        FILE *f = fopen(file, "w");
        if (!f)
            return;
        auto value = metrics_json();
        fputs(value.c_str(), f);
        fputs("\n", f);
        fclose(f);
    }
};
static Engine &engine(fuse_req_t r) { return *static_cast<Engine *>(fuse_req_userdata(r)); }
static Handle *handle(fuse_file_info *fi) { return reinterpret_cast<Handle *>(fi->fh); }
static void reply_error(fuse_req_t r, int e) { fuse_reply_err(r, e < 0 ? -e : e); }
static void init(void *userdata, fuse_conn_info *c) {
    auto &e = *static_cast<Engine *>(userdata);
    e.passthrough = fuse_set_feature_flag(c, FUSE_CAP_PASSTHROUGH);
    e.mmap = fuse_set_feature_flag(c, FUSE_CAP_DIRECT_IO_ALLOW_MMAP);
    c->max_backing_stack_depth = 0;
    fuse_unset_feature_flag(c, FUSE_CAP_WRITEBACK_CACHE);
    // No readdirplus auto lookups: callers control lookup lifetime explicitly.
    fuse_unset_feature_flag(c, FUSE_CAP_READDIRPLUS_AUTO);
    fprintf(stderr, "engine2: passthrough=%d direct_io_mmap=%d threads=%u\n", e.passthrough, e.mmap,
            std::max(2u, std::min(16u, std::thread::hardware_concurrency())));
}
static void lookup(fuse_req_t r, fuse_ino_t parent, const char *name) {
    Cred c(r);
    auto &e = engine(r);
    e.stats.lookup++;
    fuse_entry_param out{};
    int error = e.entry(r, parent, name, out);
    if (error)
        reply_error(r, error);
    else if (fuse_reply_entry(r, &out))
        e.forget(out.ino, 1);
}
static void forget(fuse_req_t r, fuse_ino_t ino, uint64_t n) {
    engine(r).forget(ino, n);
    fuse_reply_none(r);
}
static void forget_multi(fuse_req_t r, size_t count, fuse_forget_data *list) {
    for (size_t i = 0; i < count; i++)
        engine(r).forget(list[i].ino, list[i].nlookup);
    fuse_reply_none(r);
}
static void getattr(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    e.stats.getattr++;
    auto n = e.get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    struct stat st{};
    int state = 0;
    int error = e.attributes(r, n, st, &state);
    if (error)
        reply_error(r, error);
    else
        fuse_reply_attr(r, &st, state == 0 ? 1 : 0);
}
static int write_all(int fd, const void *data, size_t size, off_t off) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = pwrite(fd, static_cast<const char *>(data) + done, size - done, off + done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? errno : EIO;
        done += n;
    }
    return 0;
}
static int extend(Engine &e, int fd, off_t end) {
    struct stat st{};
    if (fstat(fd, &st))
        return errno;
    std::vector<unsigned char> block(65536);
    off_t pos = st.st_size;
    while (pos < end + 1024) {
        auto len = std::min<off_t>(block.size(), end + 1024 - pos);
        memset(block.data(), 0, len);
        e.cipher.apply(block.data(), len, pos);
        int error = write_all(fd, block.data(), len, pos);
        if (error)
            return error;
        pos += len;
    }
    return 0;
}
static int resize(Engine &e, const std::shared_ptr<Node> &n, int fd, off_t length, bool decode) {
    if (length < 0)
        return EINVAL;
    if (length > std::numeric_limits<off_t>::max() - 1024)
        return EFBIG;
    struct stat st{};
    if (fstat(fd, &st))
        return errno;
    int enc = e.classify(n, st, fd);
    if (enc != 0 && decode) {
        if (enc < 0)
            return -enc;
        int error = extend(e, fd, length);
        if (error)
            return error;
        length += 1024;
    }
    if (ftruncate(fd, length))
        return errno;
    e.invalidate(n);
    return 0;
}
static void setattr(fuse_req_t r, fuse_ino_t ino, struct stat *st, int mask, fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    std::unique_lock lock(n->storage->data);
    int error = 0;
    if (mask & FUSE_SET_ATTR_SIZE) {
        bool decoded = e.decoded(r, n);
        struct stat real{};
        if (fstat(n->fd, &real))
            error = errno;
        else {
            int state = e.classify(n, real);
            auto id = e.policy.identity(fuse_req_ctx(r)->pid);
            if (state && !decoded && !id.raw)
                error = EACCES;
            else {
                int fd = fi ? handle(fi)->fd : e.reopen(n, state ? O_RDWR : O_WRONLY);
                if (fd < 0)
                    error = errno;
                else {
                    error = resize(e, n, fd, st->st_size, decoded);
                    if (!fi)
                        close(fd);
                }
            }
        }
    }
    auto proc = Engine::proc(n->fd);
    if (!error && (mask & FUSE_SET_ATTR_MODE) && chmod(proc.c_str(), st->st_mode))
        error = errno;
    if (!error && (mask & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) &&
        chown(proc.c_str(), mask & FUSE_SET_ATTR_UID ? st->st_uid : uid_t(-1),
              mask & FUSE_SET_ATTR_GID ? st->st_gid : gid_t(-1)))
        error = errno;
    if (!error && (mask & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_ATIME_NOW |
                           FUSE_SET_ATTR_MTIME_NOW))) {
        timespec ts[2] = {st->st_atim, st->st_mtim};
        if (!(mask & FUSE_SET_ATTR_ATIME))
            ts[0].tv_nsec = UTIME_OMIT;
        if (!(mask & FUSE_SET_ATTR_MTIME))
            ts[1].tv_nsec = UTIME_OMIT;
        if (mask & FUSE_SET_ATTR_ATIME_NOW)
            ts[0].tv_nsec = UTIME_NOW;
        if (mask & FUSE_SET_ATTR_MTIME_NOW)
            ts[1].tv_nsec = UTIME_NOW;
        if (utimensat(n->fd, "", ts, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
            error = errno;
    }
    lock.unlock();
    if (error)
        reply_error(r, error);
    else
        getattr(r, ino, fi);
}
static int open_handle(fuse_req_t r, const std::shared_ptr<Node> &n, fuse_file_info *fi,
                       int created_fd = -1) {
    auto h = std::make_unique<Handle>();
    h->fd = created_fd;
    auto &e = engine(r);
    std::unique_lock lock(n->storage->data);
    struct stat st{};
    if (fstat(n->fd, &st))
        return errno;
    int state = e.classify(n, st);
    int flags = fi->flags & ~(O_TRUNC | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW);
    h->node = n;
    h->append = fi->flags & O_APPEND;
    if (state) {
        auto id = e.policy.identity(fuse_req_ctx(r)->pid);
        h->raw = id.raw;
        h->authorized = !id.raw && e.policy.trusted(id, e.path(n));
        if ((flags & O_ACCMODE) != O_RDONLY && !h->raw && !h->authorized)
            return EACCES;
        if (h->authorized && state < 0)
            return -state;
        if (h->authorized && (flags & O_ACCMODE) == O_WRONLY)
            flags = (flags & ~O_ACCMODE) | O_RDWR;
    }
    if (h->fd < 0)
        h->fd = e.reopen(n, flags);
    if (h->fd < 0)
        return errno;
    if (fi->flags & O_TRUNC) {
        int error = resize(e, n, h->fd, 0, h->authorized);
        if (error)
            return error;
    }
    if ((!state || h->raw || !h->authorized) && e.passthrough) {
        std::lock_guard g(n->storage->cache);
        bool writable = (flags & O_ACCMODE) != O_RDONLY;
        if (!n->storage->backing) {
            int backingfd = e.reopen(n, O_RDWR);
            bool rw = backingfd >= 0;
            if (!rw)
                backingfd = e.reopen(n, O_RDONLY);
            if (backingfd >= 0) {
                n->storage->backing = fuse_passthrough_open(r, backingfd);
                n->storage->backing_write = rw;
                close(backingfd);
            }
        }
        if (n->storage->backing && (!writable || n->storage->backing_write)) {
            fi->backing_id = n->storage->backing;
            n->storage->passthrough_refs++;
            h->passthrough = true;
            e.stats.passthrough++;
        }
    }
    // Raw and decoded inode IDs separate their mmap caches. Direct IO avoids
    // duplicating the normal buffered read cache for decrypted content.
    if (!h->passthrough)
        fi->direct_io = 1;
    fi->fh = reinterpret_cast<uint64_t>(h.release());
    e.stats.opens++;
    return 0;
}
static void open_file(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) {
    Cred c(r);
    auto n = engine(r).get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    int error = open_handle(r, n, fi);
    if (error)
        reply_error(r, error);
    else
        fuse_reply_open(r, fi);
}
static bool authorized(fuse_req_t r, Handle *h) {
    return fuse_req_ctx(r)->pid == 0 ? h->authorized : engine(r).decoded(r, h->node);
}
static void read_file(fuse_req_t r, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    e.stats.reads++;
    auto h = handle(fi);
    std::shared_lock lock(h->node->storage->data);
    struct stat st{};
    if (fstat(h->fd, &st)) {
        reply_error(r, errno);
        return;
    }
    int state = e.classify(h->node, st, h->fd);
    bool decode = state && authorized(r, h);
    if (decode && state < 0) {
        reply_error(r, state);
        return;
    }
    if (decode) {
        if (off >= st.st_size - 1024) {
            fuse_reply_buf(r, nullptr, 0);
            return;
        }
        size = std::min<off_t>(size, std::max<off_t>(0, st.st_size - 1024 - off));
        off += 1024;
        e.stats.cipher_reads++;
    }
    std::vector<char> data(size);
    ssize_t n = pread(h->fd, data.data(), size, off);
    if (n < 0)
        reply_error(r, errno);
    else {
        if (decode)
            e.cipher.apply(data.data(), n, off);
        fuse_reply_buf(r, data.data(), n);
    }
}
static void write_file(fuse_req_t r, fuse_ino_t ino, const char *buf, size_t size, off_t off,
                       fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    e.stats.writes++;
    auto h = handle(fi);
    std::unique_lock lock(h->node->storage->data);
    struct stat st{};
    if (fstat(h->fd, &st)) {
        reply_error(r, errno);
        return;
    }
    int state = e.classify(h->node, st, h->fd);
    bool decode = state && authorized(r, h);
    bool raw = h->raw && (fuse_req_ctx(r)->pid == 0 || e.policy.identity(fuse_req_ctx(r)->pid).raw);
    if (state && !decode && !raw) {
        reply_error(r, EACCES);
        return;
    }
    if (decode && state < 0) {
        reply_error(r, state);
        return;
    }
    if (h->append)
        off = st.st_size - (decode ? 1024 : 0);
    int error = 0;
    if (decode &&
        (off < 0 || uint64_t(off) > uint64_t(std::numeric_limits<off_t>::max()) - 1024 - size)) {
        reply_error(r, EFBIG);
        return;
    }
    if (decode) {
        error = extend(e, h->fd, off);
        off += 1024;
        e.stats.cipher_writes++;
    }
    if (!error) {
        if (decode) {
            std::vector<char> data(buf, buf + size);
            e.cipher.apply(data.data(), data.size(), off);
            error = write_all(h->fd, data.data(), size, off);
        } else
            error = write_all(h->fd, buf, size, off);
    }
    e.invalidate(h->node);
    if (error)
        reply_error(r, error);
    else
        fuse_reply_write(r, size);
}
static void release(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) {
    auto h = handle(fi);
    if (h->passthrough) {
        std::lock_guard g(h->node->storage->cache);
        if (!--h->node->storage->passthrough_refs) {
            fuse_passthrough_close(r, h->node->storage->backing);
            h->node->storage->backing = 0;
        }
    }
    auto number = h->node->ino;
    delete h;
    engine(r).collect(number);
    reply_error(r, 0);
}
static void flush(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) { reply_error(r, 0); }
static void fsync(fuse_req_t r, fuse_ino_t ino, int data, fuse_file_info *fi) {
    auto fd = handle(fi)->fd;
    reply_error(r, (data ? fdatasync(fd) : ::fsync(fd)) ? errno : 0);
}
static void create(fuse_req_t r, fuse_ino_t parent, const char *name, mode_t mode,
                   fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    int fd = openat(n->fd, name, (fi->flags & ~O_TRUNC) | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        reply_error(r, errno);
        return;
    }
    fuse_entry_param entry{};
    int error = e.entry(r, parent, name, entry);
    if (error) {
        close(fd);
        reply_error(r, error);
        return;
    }
    error = open_handle(r, e.get(entry.ino), fi, fd);
    if (error) {
        e.forget(entry.ino, 1);
        reply_error(r, error);
    } else
        fuse_reply_create(r, &entry, fi);
}
static void readlink(fuse_req_t r, fuse_ino_t ino) {
    Cred c(r);
    auto n = engine(r).get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    char buf[65536];
    auto count = readlinkat(n->fd, "", buf, sizeof(buf) - 1);
    if (count < 0)
        reply_error(r, errno);
    else {
        buf[count] = 0;
        fuse_reply_readlink(r, buf);
    }
}
static void mkdir(fuse_req_t r, fuse_ino_t parent, const char *name, mode_t mode) {
    Cred c(r);
    auto n = engine(r).get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    if (mkdirat(n->fd, name, mode))
        reply_error(r, errno);
    else
        lookup(r, parent, name);
}
static void mknod(fuse_req_t r, fuse_ino_t parent, const char *name, mode_t mode, dev_t dev) {
    Cred c(r);
    auto n = engine(r).get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    if (mknodat(n->fd, name, mode, dev))
        reply_error(r, errno);
    else
        lookup(r, parent, name);
}
static void symlink(fuse_req_t r, const char *link, fuse_ino_t parent, const char *name) {
    Cred c(r);
    auto n = engine(r).get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    if (symlinkat(link, n->fd, name))
        reply_error(r, errno);
    else
        lookup(r, parent, name);
}
static void unlink(fuse_req_t r, fuse_ino_t parent, const char *name) {
    Cred c(r);
    auto n = engine(r).get(parent);
    reply_error(r, !n ? ESTALE : unlinkat(n->fd, name, 0) ? errno : 0);
}
static void rmdir(fuse_req_t r, fuse_ino_t parent, const char *name) {
    Cred c(r);
    auto n = engine(r).get(parent);
    reply_error(r, !n ? ESTALE : unlinkat(n->fd, name, AT_REMOVEDIR) ? errno : 0);
}
static void link(fuse_req_t r, fuse_ino_t ino, fuse_ino_t parent, const char *name) {
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(ino), p = e.get(parent);
    if (!n || !p) {
        reply_error(r, ESTALE);
        return;
    }
    if (e.policy.scoped(e.path(n)) != e.policy.scoped(e.path(p) + "/" + name)) {
        reply_error(r, EXDEV);
        return;
    }
    if (linkat(AT_FDCWD, Engine::proc(n->fd).c_str(), p->fd, name, AT_SYMLINK_FOLLOW))
        reply_error(r, errno);
    else
        lookup(r, parent, name);
}
// Implement atomic editor saves at the storage boundary. The original encrypted
// destination supplies the header; plaintext sources are transformed in a hidden
// same-directory inode before rename. Existing source bytes remain recoverable.
static int preserve_rename(Engine &e, fuse_req_t r, const std::shared_ptr<Node> &from,
                           const char *name, const std::shared_ptr<Node> &to, const char *target,
                           unsigned flags) {
    auto native = [&]() {
        return syscall(SYS_renameat2, from->fd, name, to->fd, target, flags) ? errno : 0;
    };
    auto sourcepath = e.path(from) + "/" + name, targetpath = e.path(to) + "/" + target;
    if (!e.policy.scoped(targetpath))
        return native();
    auto id = e.policy.identity(fuse_req_ctx(r)->pid);
    if (id.raw)
        return native();
    int dest = openat(to->fd, target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (dest < 0)
        return errno == ENOENT || errno == ELOOP ? native() : errno;
    struct stat ds{};
    if (fstat(dest, &ds)) {
        int error = errno;
        close(dest);
        return error;
    }
    if (!S_ISREG(ds.st_mode)) {
        close(dest);
        return native();
    }
    std::array<unsigned char, 1024> header{};
    int de = header_state(dest, header, e.policy);
    close(dest);
    int source = openat(from->fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0)
        return errno == ELOOP && de ? EOPNOTSUPP : native();
    struct stat ss{};
    if (fstat(source, &ss)) {
        int error = errno;
        close(source);
        return error;
    }
    if (!S_ISREG(ss.st_mode)) {
        close(source);
        return de ? EOPNOTSUPP : native();
    }
    std::array<unsigned char, 1024> src_header{};
    // A cipher file may use a temporary extension. Signature detection here is
    // independent of source scope, just as the original preservation engine.
    int se = header_state(source, src_header, e.policy);
    if (se < 0 || de < 0) {
        close(source);
        return se < 0 ? -se : -de;
    }
    if (se == de) {
        close(source);
        return native();
    }
    int error = 0;
    if (!e.policy.trusted(id, targetpath))
        error = EACCES;
    else if (flags)
        error = flags == RENAME_NOREPLACE ? EEXIST : EOPNOTSUPP;
    else if (from->ino != to->ino || ss.st_nlink != 1)
        error = EOPNOTSUPP;
    struct stat parent{};
    if (!error && fstat(to->fd, &parent))
        error = errno;
    auto uid = fuse_req_ctx(r)->uid;
    if (!error && (parent.st_mode & S_ISVTX) && uid && uid != parent.st_uid &&
        (uid != ss.st_uid || uid != ds.st_uid))
        error = EPERM;
    if (!error && syscall(SYS_faccessat2, to->fd, "", W_OK | X_OK, AT_EMPTY_PATH | AT_EACCESS))
        error = errno;
    if (error) {
        close(source);
        return error;
    }
    // Source and destination views share storage locks, including concurrent
    // append/mmap writeback; no global cipher lock serializes unrelated files.
    auto a = e.storage(ss), b = e.storage(ds);
    std::unique_lock<std::shared_mutex> al(a->data, std::defer_lock), bl(b->data, std::defer_lock);
    if (a == b)
        al.lock();
    else
        std::lock(al, bl);
    static std::atomic<unsigned long> serial{};
    std::string temp = ".ytfs-save-" + std::to_string(getpid()) + "-" + std::to_string(serial++);
    int out = openat(to->fd, temp.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0) {
        error = errno;
        close(source);
        return error;
    }
    if (de)
        error = write_all(out, header.data(), header.size(), 0);
    std::vector<char> data(65536);
    off_t pos = 0, total = ss.st_size - (se ? 1024 : 0);
    while (!error && pos < total) {
        auto count = pread(source, data.data(), std::min<off_t>(data.size(), total - pos),
                           pos + (se ? 1024 : 0));
        if (count <= 0) {
            error = count < 0 ? errno : EIO;
            break;
        }
        if (se)
            e.cipher.apply(data.data(), count, pos + 1024);
        if (de)
            e.cipher.apply(data.data(), count, pos + 1024);
        error = write_all(out, data.data(), count, pos + (de ? 1024 : 0));
        pos += count;
    }
    if (!error && fchmod(out, ss.st_mode & 0777))
        error = errno;
    if (!error && ::fsync(out))
        error = errno;
    struct stat after{};
    if (!error && fstat(source, &after))
        error = errno;
    if (!error &&
        (ss.st_size != after.st_size || ss.st_mtim.tv_sec != after.st_mtim.tv_sec ||
         ss.st_mtim.tv_nsec != after.st_mtim.tv_nsec || ss.st_ctim.tv_sec != after.st_ctim.tv_sec ||
         ss.st_ctim.tv_nsec != after.st_ctim.tv_nsec))
        error = EAGAIN;
    close(source);
    close(out);
    if (!error && renameat(to->fd, temp.c_str(), to->fd, target))
        error = errno;
    if (!error && unlinkat(from->fd, name, 0))
        error = errno;
    if (error)
        unlinkat(to->fd, temp.c_str(), 0);
    return error;
}
static void rename(fuse_req_t r, fuse_ino_t parent, const char *name, fuse_ino_t newparent,
                   const char *target, unsigned flags) {
    Cred c(r);
    auto &e = engine(r);
    auto p = e.get(parent), q = e.get(newparent);
    if (!p || !q) {
        reply_error(r, ESTALE);
        return;
    }
    auto oldpath = e.path(p) + "/" + name, newpath = e.path(q) + "/" + target;
    int error = preserve_rename(e, r, p, name, q, target, flags);
    if (!error) {
        std::lock_guard g(e.nodes_lock);
        for (auto &[id, n] : e.nodes) {
            if (n->path == oldpath || n->path.starts_with(oldpath + "/")) {
                n->path = newpath + n->path.substr(oldpath.size());
                std::lock_guard cache(n->storage->cache);
                n->storage->classified = false;
            }
        }
    }
    reply_error(r, error);
}
static void opendir(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    int fd = e.reopen(n, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        reply_error(r, errno);
        return;
    }
    DIR *dir = fdopendir(fd);
    if (!dir) {
        int er = errno;
        close(fd);
        reply_error(r, er);
        return;
    }
    auto d = new Directory{dir, n, {}};
    fi->fh = reinterpret_cast<uint64_t>(d);
    fi->cache_readdir = 1;
    fuse_reply_open(r, fi);
}
static void readdir(fuse_req_t r, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi) {
    Cred c(r);
    auto d = reinterpret_cast<Directory *>(fi->fh);
    std::lock_guard g(d->lock);
    seekdir(d->stream, off);
    std::vector<char> data(size);
    size_t used = 0;
    errno = 0;
    while (auto ent = ::readdir(d->stream)) {
        struct stat st{};
        st.st_ino = ent->d_ino;
        st.st_mode = ent->d_type << 12;
        auto next = telldir(d->stream);
        auto len = fuse_add_direntry(r, data.data() + used, size - used, ent->d_name, &st, next);
        if (len > size - used)
            break;
        used += len;
    }
    if (!used && errno)
        reply_error(r, errno);
    else
        fuse_reply_buf(r, data.data(), used);
}
static void releasedir(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) {
    auto d = reinterpret_cast<Directory *>(fi->fh);
    auto number = d->node->ino;
    delete d;
    engine(r).collect(number);
    reply_error(r, 0);
}
static void statfs(fuse_req_t r, fuse_ino_t ino) {
    Cred c(r);
    auto n = engine(r).get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    struct statvfs st{};
    int fd = engine(r).reopen(n, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        reply_error(r, errno);
        return;
    }
    int error = fstatvfs(fd, &st) ? errno : 0;
    close(fd);
    if (error)
        reply_error(r, error);
    else
        fuse_reply_statfs(r, &st);
}
static void getxattr(fuse_req_t r, fuse_ino_t ino, const char *name, size_t size) {
    if (ino == 1 && !strcmp(name, "user.ytfs.metrics")) {
        auto value = engine(r).metrics_json();
        if (!size)
            fuse_reply_xattr(r, value.size());
        else if (size < value.size())
            reply_error(r, ERANGE);
        else
            fuse_reply_buf(r, value.data(), value.size());
        return;
    }

    Cred c(r);
    auto n = engine(r).get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    std::vector<char> buf(size);
    auto len = ::getxattr(Engine::proc(n->fd).c_str(), name, size ? buf.data() : nullptr, size);
    if (len < 0)
        reply_error(r, errno);
    else if (!size)
        fuse_reply_xattr(r, len);
    else
        fuse_reply_buf(r, buf.data(), len);
}
static void setxattr(fuse_req_t r, fuse_ino_t ino, const char *name, const char *value, size_t size,
                     int flags) {
    Cred c(r);
    auto n = engine(r).get(ino);
    reply_error(r, !n                                                                  ? ESTALE
                   : ::setxattr(Engine::proc(n->fd).c_str(), name, value, size, flags) ? errno
                                                                                       : 0);
}
static void removexattr(fuse_req_t r, fuse_ino_t ino, const char *name) {
    Cred c(r);
    auto n = engine(r).get(ino);
    reply_error(r, !n ? ESTALE : ::removexattr(Engine::proc(n->fd).c_str(), name) ? errno : 0);
}
static void listxattr(fuse_req_t r, fuse_ino_t ino, size_t size) {
    Cred c(r);
    auto n = engine(r).get(ino);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    std::vector<char> buf(size);
    auto len = ::listxattr(Engine::proc(n->fd).c_str(), size ? buf.data() : nullptr, size);
    if (len < 0)
        reply_error(r, errno);
    else if (!size)
        fuse_reply_xattr(r, len);
    else
        fuse_reply_buf(r, buf.data(), len);
}
static void flock(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi, int op) {
    reply_error(r, ::flock(handle(fi)->fd, op) ? errno : 0);
}
static ssize_t custom_read(int fd, void *buf, size_t size, void *userdata) {
    auto &e = *static_cast<Engine *>(userdata);
    for (;;) {
        auto count = ::read(fd, buf, size);
        if (count < ssize_t(sizeof(fuse_in_header)))
            return count;
        auto *request = static_cast<fuse_in_header *>(buf);
        if (request->uid == e.owner || request->uid == 0)
            return count;
        fuse_out_header denied{};
        denied.len = sizeof(denied);
        denied.error = -EACCES;
        denied.unique = request->unique;
        if (::write(fd, &denied, sizeof(denied)) != sizeof(denied)) {
            errno = EIO;
            return -1;
        }
    }
}
static ssize_t custom_write(int fd, iovec *buf, int count, void *) {
    return writev(fd, buf, count);
}
int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "usage: engine2 BACKING POLICY FUSE_FD METRICS OWNER_UID\n");
        return 2;
    }
    try {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        rlimit descriptors{};
        if (!getrlimit(RLIMIT_NOFILE, &descriptors)) {
            descriptors.rlim_cur = descriptors.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &descriptors))
                throw std::runtime_error("cannot raise descriptor soft limit");
        }
        Engine e(argv[1], argv[2]);
        e.owner = static_cast<uid_t>(std::stoul(argv[5]));
        fuse_lowlevel_ops ops{};
        ops.init = init;
        ops.lookup = lookup;
        ops.forget = forget;
        ops.forget_multi = forget_multi;
        ops.getattr = getattr;
        ops.setattr = setattr;
        ops.readlink = readlink;
        ops.mknod = mknod;
        ops.mkdir = mkdir;
        ops.unlink = unlink;
        ops.rmdir = rmdir;
        ops.symlink = symlink;
        ops.rename = rename;
        ops.link = link;
        ops.open = open_file;
        ops.read = read_file;
        ops.write = write_file;
        ops.flush = flush;
        ops.release = release;
        ops.fsync = fsync;
        ops.opendir = opendir;
        ops.readdir = readdir;
        ops.releasedir = releasedir;
        ops.statfs = statfs;
        ops.getxattr = getxattr;
        ops.setxattr = setxattr;
        ops.removexattr = removexattr;
        ops.listxattr = listxattr;
        ops.create = create;
        ops.flock = flock;
        char arg0[] = "ytfs-engine2";
        char debug[] = "-d";
        char *arguments[] = {arg0, debug};
        fuse_args args = FUSE_ARGS_INIT(getenv("YT_ENGINE_DEBUG") ? 2 : 1, arguments);
        auto session = fuse_session_new(&args, &ops, sizeof(ops), &e);
        if (!session)
            throw std::runtime_error("fuse_session_new failed");
        fuse_custom_io io{};
        io.read = custom_read;
        io.writev = custom_write;
        if (fuse_session_custom_io(session, &io, sizeof(io), atoi(argv[3])))
            throw std::runtime_error("custom fuse fd failed");
        fuse_set_signal_handlers(session);
        auto cfg = fuse_loop_cfg_create();
        fuse_loop_cfg_set_clone_fd(cfg, 0);
        fuse_loop_cfg_set_max_threads(
            cfg, std::max(2u, std::min(16u, std::thread::hardware_concurrency())));
        int status = fuse_session_loop_mt(session, cfg);
        fuse_loop_cfg_destroy(cfg);
        fuse_remove_signal_handlers(session);
        e.metrics(argv[4]);
        fuse_session_destroy(session);
        fuse_opt_free_args(&args);
        return status ? 1 : 0;
    } catch (const std::exception &error) {
        fprintf(stderr, "engine2: %s\n", error.what());
        return 1;
    }
}
