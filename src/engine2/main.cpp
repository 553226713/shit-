#define FUSE_USE_VERSION 318
#include "cipher.hpp"
#include "policy.hpp"
#include "error_log.hpp"
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <dirent.h>
#include <fuse_lowlevel.h>
#include <grp.h>
#include <limits>
#include <linux/fuse.h>
#include <linux/openat2.h>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <signal.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <system_error>
#include <thread>
#include <tuple>
#include <vector>

// This engine is deliberately independent of the production launcher. Only the
// mount broker owns CAP_SYS_ADMIN; backing filesystem access uses request fsuid.
struct Cred {
    uid_t uid;
    gid_t gid;
    std::vector<gid_t> groups;
    explicit Cred(fuse_req_t r) {
        auto c = fuse_req_ctx(r);
        int count = getgroups(0, nullptr);
        if (count < 0)
            throw std::system_error(errno, std::generic_category(), "getgroups");
        groups.resize(count);
        if (getgroups(count, groups.data()) < 0)
            throw std::system_error(errno, std::generic_category(), "getgroups");
        std::vector<gid_t> requested;
        if (c->pid > 0) {
            count = fuse_req_getgroups(r, 0, nullptr);
            if (count < 0)
                throw std::system_error(-count, std::generic_category(), "request groups");
            for (;;) {
                requested.resize(count);
                int actual = fuse_req_getgroups(r, count, requested.data());
                if (actual < 0)
                    throw std::system_error(-actual, std::generic_category(), "request groups");
                if (actual <= count) {
                    requested.resize(actual);
                    break;
                }
                count = actual;
            }
        }
        // Credentials belong to this worker thread. libc setgroups would
        // change every thread and race concurrent requests from other users.
        if (syscall(SYS_setgroups, requested.size(), requested.data()))
            throw std::system_error(errno, std::generic_category(), "setgroups");
        gid = setfsgid(c->gid);
        uid = setfsuid(c->uid);
    }
    ~Cred() {
        setfsuid(uid);
        setfsgid(gid);
        if (syscall(SYS_setgroups, groups.size(), groups.data()))
            std::terminate();
    }
};
struct Storage {
    std::shared_mutex data;
    std::mutex cache;
    struct Stamp {
        off_t size = 0;
        timespec modified{}, changed{};
    } stamp;
    bool classified = false;
    int state = 0;
    int backing = 0;
    bool backing_write = false;
    unsigned passthrough_refs = 0;
};
struct Node {
    int fd;
    dev_t device = 0;
    ino_t physical_ino = 0;
    bool fd_cached = false;
    bool retired = false;
    std::list<fuse_ino_t>::iterator fd_position;
    fuse_ino_t ino;
    uint64_t refs = 0;
    std::string path;
    bool gc_queued = false;
    int view = 0; // 0 ordinary, 1 decoded, 2 ciphertext: separate kernel caches.
    std::shared_ptr<Storage> storage;
    Node(int f, fuse_ino_t i, std::string p) : fd(f), ino(i), path(std::move(p)) {}
    ~Node() {
        if (fd >= 0)
            close(fd);
    }
};
struct Handle {
    int fd;
    std::shared_ptr<Node> node;
    std::string path;
    bool passthrough = false, authorized = false, raw_git = false, append = false, writable = false;
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
    std::mutex namespace_lock;
    std::map<fuse_ino_t, std::shared_ptr<Node>> nodes;
    std::map<std::tuple<dev_t, ino_t, int>, fuse_ino_t> identity;
    std::deque<fuse_ino_t> garbage;
    std::list<fuse_ino_t> fd_lru;
    size_t fd_budget = 128;
    uint64_t fd_evictions = 0, fd_reopens = 0;
    fuse_ino_t next = 2;
    bool passthrough = false, mmap = false;
    Counters stats;
    int fuse_fd = -1;
    explicit Engine(const char *root, const char *config) : policy(config) {
        int fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0)
            throw std::runtime_error("backing directory cannot be opened");
        struct stat root_stat{};
        if (fstat(fd, &root_stat))
            throw std::runtime_error("backing stat failed");
        auto n = std::make_shared<Node>(fd, 1, "");
        n->device = root_stat.st_dev;
        n->physical_ino = root_stat.st_ino;
        n->storage = std::make_shared<Storage>();
        n->refs = 1;
        nodes[1] = n;
        rlimit limit{};
        if (!getrlimit(RLIMIT_NOFILE, &limit))
            fd_budget = std::max<size_t>(16, std::min<rlim_t>(4096, limit.rlim_cur / 4));
    }
    // Kernel inode references are not active userspace operations. Retain a
    // bounded cache of their O_PATH descriptors, while preserving descriptors
    // held by open handles and in-flight callbacks. No repository size limit.
    void trim_fds(size_t target) {
        auto attempts = fd_lru.size();
        while (fd_lru.size() > target && attempts--) {
            auto current = fd_lru.begin();
            auto found = nodes.find(*current);
            if (found == nodes.end()) {
                fd_lru.erase(current);
                continue;
            }
            auto &n = found->second;
            if (n.use_count() != 1) {
                fd_lru.splice(fd_lru.end(), fd_lru, current);
                continue;
            }
            close(n->fd);
            n->fd = -1;
            n->fd_cached = false;
            fd_lru.erase(current);
            fd_evictions++;
        }
    }
    void track_fd(const std::shared_ptr<Node> &n) {
        if (n->ino == 1)
            return;
        if (n->fd_cached)
            fd_lru.splice(fd_lru.end(), fd_lru, n->fd_position);
        else {
            fd_lru.push_back(n->ino);
            n->fd_position = std::prev(fd_lru.end());
            n->fd_cached = true;
        }
    }
    bool ensure_fd(const std::shared_ptr<Node> &n) {
        if (n->fd >= 0) {
            track_fd(n);
            return true;
        }
        if (n->retired) {
            errno = ESTALE;
            return false;
        }
        trim_fds(fd_budget - 1);
        open_how how{};
        how.flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
        how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS;
        auto relative = n->path.starts_with('/') ? n->path.substr(1) : n->path;
        int fd = syscall(SYS_openat2, nodes.at(1)->fd, relative.c_str(), &how, sizeof(how));
        if (fd < 0)
            return false;
        struct stat st{};
        if (fstat(fd, &st) || st.st_dev != n->device || st.st_ino != n->physical_ino) {
            close(fd);
            errno = ESTALE;
            return false;
        }
        n->fd = fd;
        try {
            track_fd(n);
        } catch (...) {
            close(fd);
            n->fd = -1;
            throw;
        }
        fd_reopens++;
        return true;
    }
    std::shared_ptr<Node> get(fuse_ino_t ino) {
        std::lock_guard g(nodes_lock);
        auto it = nodes.find(ino);
        if (it == nodes.end())
            return nullptr;
        auto n = it->second;
        if (!ensure_fd(n))
            return nullptr;
        return n;
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
            if (n->fd < 0) {
                n->fd = candidate->fd;
                n->path = candidate->path;
                candidate->fd = -1;
                fd_reopens++;
            }
            track_fd(n);
            n->refs++;
            trim_fds(fd_budget);
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
        candidate->device = st.st_dev;
        candidate->physical_ino = st.st_ino;
        nodes.emplace(candidate->ino, candidate);
        try {
            identity.emplace(key, candidate->ino);
            track_fd(candidate);
        } catch (...) {
            identity.erase(key);
            nodes.erase(candidate->ino);
            throw;
        }
        trim_fds(fd_budget);
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
        auto mapped = identity.find({n->device, n->physical_ino, n->view});
        if (mapped != identity.end() && mapped->second == n->ino)
            identity.erase(mapped);
        if (n->fd_cached) {
            fd_lru.erase(n->fd_position);
            n->fd_cached = false;
        }
        nodes.erase(n->ino);
    }
    void retire_inode(const struct stat &st) {
        std::lock_guard g(nodes_lock);
        for (int view = 0; view < 3; view++) {
            auto mapped = identity.find({st.st_dev, st.st_ino, view});
            if (mapped == identity.end())
                continue;
            nodes.at(mapped->second)->retired = true;
            identity.erase(mapped);
        }
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
        if (!S_ISREG(st.st_mode) || st.st_size < 32)
            return 0;
        std::lock_guard g(n->storage->cache);
        auto &a = n->storage->stamp;
        if (n->storage->classified && a.size == st.st_size &&
            a.modified.tv_sec == st.st_mtim.tv_sec && a.modified.tv_nsec == st.st_mtim.tv_nsec &&
            a.changed.tv_sec == st.st_ctim.tv_sec && a.changed.tv_nsec == st.st_ctim.tv_nsec)
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
            n->storage->stamp = {st.st_size, st.st_mtim, st.st_ctim};
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
        return policy.trusted(id, path(n));
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
        auto relative = path(dir) + "/" + name;
        struct stat current{};
        if (fstatat(dir->fd, name, &current, AT_SYMLINK_NOFOLLOW))
            return errno;
        {
            std::lock_guard g(nodes_lock);
            sweep();
            auto found = identity.find({current.st_dev, current.st_ino, 0});
            if (found != identity.end()) {
                auto n = nodes.at(found->second);
                std::lock_guard cache(n->storage->cache);
                auto &stamp = n->storage->stamp;
                bool unchanged_plain = n->storage->classified && n->storage->state == 0 &&
                    stamp.size == current.st_size &&
                    stamp.modified.tv_sec == current.st_mtim.tv_sec &&
                    stamp.modified.tv_nsec == current.st_mtim.tv_nsec &&
                    stamp.changed.tv_sec == current.st_ctim.tv_sec &&
                    stamp.changed.tv_nsec == current.st_ctim.tv_nsec;
                // Revalidate the backing inode and timestamps, but do not open
                // a descriptor just to report unchanged plaintext metadata.
                // Keep the descriptor reopen path tied to this directory entry.
                if (n->path == relative && !n->retired &&
                    (!S_ISREG(current.st_mode) || current.st_size < 32 || unchanged_plain)) {
                    n->refs++;
                    entry = {};
                    entry.ino = n->ino;
                    entry.generation = 1;
                    entry.attr = current;
                    entry.entry_timeout = S_ISREG(current.st_mode) ? 0 : 1;
                    entry.attr_timeout = 1;
                    return 0;
                }
            }
        }
        {
            std::lock_guard g(nodes_lock);
            trim_fds(fd_budget > 16 ? fd_budget - 16 : 0);
        }
        int fd = openat(dir->fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            return errno;
        struct stat st{};
        if (fstat(fd, &st)) {
            int error = errno;
            close(fd);
            return error;
        }
        auto candidate = std::make_shared<Node>(fd, 0, relative);
        candidate->storage = storage(st);
        int enc = classify(candidate, st);
        candidate->view = enc ? (decoded(req, candidate) ? 1 : 2) : 0;
        auto n = add(candidate, st);
        entry = {};
        entry.ino = n->ino;
        entry.generation = 1;
        // The descriptor and stat above already describe this lookup. Repeating
        // fstat/classification here doubles metadata work during IDE scans.
        entry.attr = st;
        if (enc == 1 && n->view == 1)
            entry.attr.st_size = std::max<off_t>(0, st.st_size - 1024);
        // Regular dentries must revalidate, including editor temporary
        // files: rename preservation can replace their backing inode when an
        // editor saves over a ciphertext target.
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
            "\"cipher_reads\":%lu,\"cipher_writes\":%lu,\"header_probes\":%lu,\"live_nodes\":%zu,"
            "\"cached_node_fds\":%zu,\"fd_cache_budget\":%zu,\"fd_evictions\":%lu,\"fd_reopens\":%"
            "lu}",
            passthrough ? "true" : "false", mmap ? "true" : "false", stats.lookup.load(),
            stats.getattr.load(), stats.opens.load(), stats.passthrough.load(), stats.reads.load(),
            stats.writes.load(), stats.cipher_reads.load(), stats.cipher_writes.load(),
            stats.header_probes.load(), nodes.size(), fd_lru.size() + 1, fd_budget, fd_evictions,
            fd_reopens);
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
static bool authorized(fuse_req_t r, Handle *h) {
    if (fuse_req_ctx(r)->pid == 0)
        return h->authorized;
    auto &e = engine(r);
    auto id = e.policy.identity(fuse_req_ctx(r)->pid);
    return e.policy.trusted(id, h->path);
}
static bool raw_transport(fuse_req_t r, Handle *h = nullptr) {
    if (fuse_req_ctx(r)->pid == 0)
        return h && h->raw_git;
    return engine(r).policy.identity(fuse_req_ctx(r)->pid).raw_git;
}
static void reply_error(fuse_req_t r, int e) {
    e = e < 0 ? -e : e;
    switch (e) {
    case EIO: case ENOMEM: case EMFILE: case ENFILE: case ENOSPC: case EDQUOT:
    case EROFS: case ENOTCONN: case ETIMEDOUT: case EOVERFLOW:
        errors::report(e, fuse_req_ctx(r)->pid, fuse_req_ctx(r)->uid, strerror(e));
    }
    fuse_reply_err(r, e);
}
static void init(void *userdata, fuse_conn_info *c) {
    auto &e = *static_cast<Engine *>(userdata);
    e.passthrough = fuse_set_feature_flag(c, FUSE_CAP_PASSTHROUGH);
    e.mmap = fuse_set_feature_flag(c, FUSE_CAP_DIRECT_IO_ALLOW_MMAP);
    c->max_backing_stack_depth = 0;
    fuse_unset_feature_flag(c, FUSE_CAP_WRITEBACK_CACHE);
    // No readdirplus auto lookups: callers control lookup lifetime explicitly.
    fuse_unset_feature_flag(c, FUSE_CAP_READDIRPLUS_AUTO);
}
static void forget_safely(Engine &e, fuse_ino_t ino) noexcept {
    try {
        e.forget(ino, 1);
    } catch (...) {
        errors::report(EIO, 0, 0, "deferred lookup cleanup failed");
    }
}
static void discard_handle(Engine &e, Handle *h) noexcept {
    try {
        if (h->writable)
            e.invalidate(h->node);
        if (h->passthrough) {
            std::lock_guard g(h->node->storage->cache);
            if (!--h->node->storage->passthrough_refs) {
                uint32_t id = h->node->storage->backing;
                ioctl(e.fuse_fd, FUSE_DEV_IOC_BACKING_CLOSE, &id);
                h->node->storage->backing = 0;
            }
        }
        auto ino = h->node->ino;
        delete h;
        e.collect(ino);
    } catch (...) {
        errors::report(EIO, 0, 0, "handle cleanup failed");
    }
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
        forget_safely(e, out.ino);
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
        bool decoded = fi ? authorized(r, handle(fi)) : e.decoded(r, n);
        struct stat real{};
        if (fstat(n->fd, &real))
            error = errno;
        else {
            int state = e.classify(n, real);
            if ((state && !decoded && !raw_transport(r, fi ? handle(fi) : nullptr)) ||
                (fi && handle(fi)->raw_git && !raw_transport(r, handle(fi))))
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
    h->path = e.path(n);
    struct stat st{};
    if (fstat(n->fd, &st))
        return errno;
    int state = e.classify(n, st);
    int flags = fi->flags & ~(O_TRUNC | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW);
    h->node = n;
    h->append = fi->flags & O_APPEND;
    h->writable = (fi->flags & O_ACCMODE) != O_RDONLY;
    auto id = e.policy.identity(fuse_req_ctx(r)->pid);
    h->raw_git = id.raw_git;
    h->authorized = e.policy.trusted(id, h->path);
    if (state) {
        if ((flags & O_ACCMODE) != O_RDONLY && !h->authorized && !h->raw_git)
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
    // Writable passthrough would bypass per-request authorization after FD passing.
    if ((!state || !h->authorized) && e.passthrough && !h->writable) {
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
    else {
        auto &e = engine(r);
        auto h = handle(fi);
        if (fuse_reply_open(r, fi))
            discard_handle(e, h);
    }
}
static void read_file(fuse_req_t r, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi) {
    Cred c(r);
    auto &e = engine(r);
    e.stats.reads++;
    auto h = handle(fi);
    // A reply permits RELEASE/FORGET on another worker before this callback
    // returns. Keep the mutex owner alive until the lock has been destroyed.
    auto node = h->node;
    std::shared_lock lock(node->storage->data);
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
    auto node = h->node;
    std::unique_lock lock(node->storage->data);
    struct stat st{};
    if (fstat(h->fd, &st)) {
        reply_error(r, errno);
        return;
    }
    int state = e.classify(h->node, st, h->fd);
    bool decode = state && authorized(r, h);
    if ((state && !decode && !raw_transport(r, h)) ||
        (h->raw_git && !raw_transport(r, h))) {
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
    discard_handle(engine(r), handle(fi));
    reply_error(r, 0);
}
static void flush(fuse_req_t r, fuse_ino_t ino, fuse_file_info *fi) { reply_error(r, 0); }
static void fsync(fuse_req_t r, fuse_ino_t ino, int data, fuse_file_info *fi) {
    auto fd = handle(fi)->fd;
    reply_error(r, (data ? fdatasync(fd) : ::fsync(fd)) ? errno : 0);
}
static int creation_format(fuse_req_t r, const std::string &path, bool &encrypt) {
    auto &e = engine(r);
    encrypt = false;
    auto id = e.policy.identity(fuse_req_ctx(r)->pid);
    if (id.raw_git || !e.policy.encrypt_new)
        return 0;
    if (!e.policy.trusted(id, path))
        return EACCES;
    encrypt = true;
    return 0;
}
static int write_new_header(Engine &e, int fd) {
    // Format 301 layout: native BuildCipherHeader (0x407f6c) and the Windows
    // driver's new-header path (0x14000ebb4). No machine identity is copied.
    std::array<unsigned char, 1024> header{};
    std::copy(MAGIC.begin(), MAGIC.end(), header.begin());
    std::copy(MAGIC.begin(), MAGIC.end(), header.begin() + 32);
    e.cipher.apply(header.data() + 32, 32, 0);
    const unsigned char version[] = {0x60, 0x38, 0x58, 0x03};
    memcpy(header.data() + 65, version, sizeof(version));
    header[85] = 0x2d;
    header[86] = 1;
    memcpy(header.data() + 213, e.policy.key.c_str(), e.policy.key.size() + 1);
    memcpy(header.data() + 243, "level0", 6);
    for (size_t i = 243; i < 252; i++)
        header[i] ^= 0xfd;
    header[253] = 0x30;
    memcpy(header.data() + 278, "2020.NewDriver-Pading", 21);
    memcpy(header.data() + 1019, "[END]", 5);
    return write_all(fd, header.data(), header.size(), 0);
}
static void create(fuse_req_t r, fuse_ino_t parent, const char *name, mode_t mode,
                   fuse_file_info *fi) {
    std::lock_guard namespace_guard(engine(r).namespace_lock);
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    bool encrypt = false;
    int error = creation_format(r, e.path(n) + "/" + name, encrypt);
    if (error) {
        reply_error(r, error);
        return;
    }
    int flags = fi->flags & ~O_TRUNC;
    if (encrypt)
        flags = (flags & ~O_ACCMODE) | O_RDWR;
    int fd = openat(n->fd, name, flags | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        reply_error(r, errno);
        return;
    }
    if (encrypt && (error = write_new_header(e, fd))) {
        close(fd);
        unlinkat(n->fd, name, 0);
        reply_error(r, error);
        return;
    }
    fuse_entry_param entry{};
    error = e.entry(r, parent, name, entry);
    if (error) {
        close(fd);
        reply_error(r, error);
        return;
    }
    error = open_handle(r, e.get(entry.ino), fi, fd);
    if (error) {
        e.forget(entry.ino, 1);
        reply_error(r, error);
    } else {
        auto h = handle(fi);
        if (fuse_reply_create(r, &entry, fi)) {
            discard_handle(e, h);
            forget_safely(e, entry.ino);
        }
    }
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
    std::lock_guard namespace_guard(engine(r).namespace_lock);
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
    std::lock_guard namespace_guard(engine(r).namespace_lock);
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    if (S_ISREG(mode) && e.policy.encrypt_new) {
        bool encrypt = false;
        int error = creation_format(r, e.path(n) + "/" + name, encrypt);
        if (error) {
            reply_error(r, error);
            return;
        }
        if (encrypt) {
            int fd = openat(n->fd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, mode);
            if (fd < 0) {
                reply_error(r, errno);
                return;
            }
            error = write_new_header(e, fd);
            close(fd);
            if (error) {
                unlinkat(n->fd, name, 0);
                reply_error(r, error);
            } else
                lookup(r, parent, name);
            return;
        }
    }
    if (mknodat(n->fd, name, mode, dev))
        reply_error(r, errno);
    else
        lookup(r, parent, name);
}
static void symlink(fuse_req_t r, const char *link, fuse_ino_t parent, const char *name) {
    std::lock_guard namespace_guard(engine(r).namespace_lock);
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
static void remove_entry(fuse_req_t r, fuse_ino_t parent, const char *name, int flags) {
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(parent);
    if (!n) {
        reply_error(r, ESTALE);
        return;
    }
    struct stat before{};
    bool known = !fstatat(n->fd, name, &before, AT_SYMLINK_NOFOLLOW);
    if (unlinkat(n->fd, name, flags)) {
        reply_error(r, errno);
        return;
    }
    if (known && (flags == AT_REMOVEDIR || before.st_nlink == 1))
        e.retire_inode(before);
    reply_error(r, 0);
}
static void unlink(fuse_req_t r, fuse_ino_t parent, const char *name) {
    std::lock_guard namespace_guard(engine(r).namespace_lock);
    remove_entry(r, parent, name, 0);
}
static void rmdir(fuse_req_t r, fuse_ino_t parent, const char *name) {
    std::lock_guard namespace_guard(engine(r).namespace_lock);
    remove_entry(r, parent, name, AT_REMOVEDIR);
}
static void link(fuse_req_t r, fuse_ino_t ino, fuse_ino_t parent, const char *name) {
    std::lock_guard namespace_guard(engine(r).namespace_lock);
    Cred c(r);
    auto &e = engine(r);
    auto n = e.get(ino), p = e.get(parent);
    if (!n || !p) {
        reply_error(r, ESTALE);
        return;
    }
    if (linkat(AT_FDCWD, Engine::proc(n->fd).c_str(), p->fd, name, AT_SYMLINK_FOLLOW))
        reply_error(r, errno);
    else
        lookup(r, parent, name);
}
static int encrypted_replacement(fuse_req_t r, int dir, const char *name, int dest,
                                 const char *target, const std::string &source_path,
                                 const std::string &target_path, bool &handled) {
    handled = false;
    auto &e = engine(r);
    if (raw_transport(r))
        return 0;
    // Signature probing may elevate only to classify bytes, never to copy
    // content. Ordinary renames require directory rights, not file read rights.
    auto signature = [&](int parent, const char *entry,
                         std::array<unsigned char, 1024> &header) {
        struct stat st{};
        if (fstatat(parent, entry, &st, AT_SYMLINK_NOFOLLOW))
            return -errno;
        if (!S_ISREG(st.st_mode) || st.st_size < 32)
            return 0;
        int fd = openat(parent, entry, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 && errno == EACCES) {
            auto previous = setfsuid(0);
            fd = openat(parent, entry, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
            int error = errno;
            setfsuid(previous);
            errno = error;
        }
        if (fd < 0)
            return -errno;
        int state = header_state(fd, header, e.policy);
        close(fd);
        return state;
    };
    std::array<unsigned char, 1024> header{}, scratch{};
    int target_state = signature(dest, target, header);
    if (!target_state)
        return 0;
    int source_state = signature(dir, name, scratch);
    if (source_state > 0)
        return 0;
    handled = true;
    if (target_state < 0 || source_state < 0)
        return target_state < 0 ? -target_state : -source_state;
    auto id = e.policy.identity(fuse_req_ctx(r)->pid);
    if (!e.policy.trusted(id, source_path) || !e.policy.trusted(id, target_path))
        return EACCES;
    int from = openat(dir, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (from < 0)
        return errno;
    std::string temporary;
    int staged = -1;
    struct Cleanup {
        int dir, from;
        int &staged;
        std::string &temporary;
        bool preserve = false;
        ~Cleanup() {
            close(from);
            if (staged >= 0) {
                close(staged);
                if (!preserve) unlinkat(dir, temporary.c_str(), 0);
            }
        }
    } cleanup{dir, from, staged, temporary};
    int to = openat(dest, target, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (to < 0) return errno;
    int target_check = header_state(to, header, e.policy);
    close(to);
    int error = target_check == 1 ? 0 : target_check < 0 ? -target_check : EAGAIN;
    struct stat metadata{};
    if (!error && fstat(from, &metadata))
        error = errno;
    static std::atomic<uint64_t> serial{};
    for (unsigned attempt = 0; !error && attempt < 100; ++attempt) {
        temporary = ".cipher-save-" + std::to_string(getpid()) + "-" + std::to_string(serial++);
        staged = openat(dir, temporary.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (staged >= 0) break;
        if (errno != EEXIST) error = errno;
    }
    if (!error && staged < 0) error = EEXIST;
    if (!error) error = write_all(staged, header.data(), header.size(), 0);
    std::array<unsigned char, 65536> buffer{};
    off_t offset = 0;
    while (!error) {
        ssize_t count = pread(from, buffer.data(), buffer.size(), offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { error = errno; break; }
        if (!count) break;
        e.cipher.apply(buffer.data(), count, offset + 1024);
        error = write_all(staged, buffer.data(), count, offset + 1024);
        offset += count;
    }
    if (!error && fchown(staged, metadata.st_uid, metadata.st_gid)) error = errno;
    if (!error) {
        ssize_t count = flistxattr(from, nullptr, 0);
        if (count < 0 && errno != ENOTSUP) error = errno;
        if (count > 0) {
            std::vector<char> names(count);
            if (flistxattr(from, names.data(), names.size()) != count) error = errno ? errno : EIO;
            for (size_t pos = 0; !error && pos < names.size();) {
                const char *key = names.data() + pos;
                ssize_t size = fgetxattr(from, key, nullptr, 0);
                if (size < 0) { error = errno; break; }
                std::vector<char> value(size);
                if (fgetxattr(from, key, value.data(), value.size()) != size ||
                    fsetxattr(staged, key, value.data(), value.size(), 0)) error = errno ? errno : EIO;
                pos += strlen(key) + 1;
            }
        }
    }
    timespec times[] = {metadata.st_atim, metadata.st_mtim};
    if (!error && (fchmod(staged, metadata.st_mode & 07777) || futimens(staged, times) || ::fsync(staged)))
        error = errno;
    if (!error && syscall(SYS_renameat2, dir, temporary.c_str(), dir, name, RENAME_EXCHANGE))
        error = errno;
    else if (!error && syscall(SYS_renameat2, dir, name, dest, target, 0)) {
        error = errno;
        if (syscall(SYS_renameat2, dir, temporary.c_str(), dir, name, RENAME_EXCHANGE)) {
            cleanup.preserve = true;
            return EIO; // Preserve both inodes if external backing changes prevent rollback.
        }
    }
    return error;
}
static void rename(fuse_req_t r, fuse_ino_t parent, const char *name, fuse_ino_t newparent,
                   const char *target, unsigned flags) {
    std::lock_guard namespace_guard(engine(r).namespace_lock);
    Cred c(r);
    auto &e = engine(r);
    auto p = e.get(parent), q = e.get(newparent);
    if (!p || !q) {
        reply_error(r, ESTALE);
        return;
    }
    auto oldpath = e.path(p) + "/" + name, newpath = e.path(q) + "/" + target;
    struct stat old_source{}, old_target{};
    bool source_known = !fstatat(p->fd, name, &old_source, AT_SYMLINK_NOFOLLOW);
    bool target_known = !fstatat(q->fd, target, &old_target, AT_SYMLINK_NOFOLLOW);
    bool handled = false;
    int error = 0;
    if (!flags && source_known && target_known && S_ISREG(old_source.st_mode) &&
        S_ISREG(old_target.st_mode) &&
        (old_source.st_dev != old_target.st_dev || old_source.st_ino != old_target.st_ino)) {
        auto source_storage = e.storage(old_source), target_storage = e.storage(old_target);
        std::unique_lock source_lock(source_storage->data, std::defer_lock);
        std::unique_lock target_lock(target_storage->data, std::defer_lock);
        std::lock(source_lock, target_lock);
        error = encrypted_replacement(r, p->fd, name, q->fd, target, oldpath, newpath, handled);
    }
    if (!error && !handled)
        error = syscall(SYS_renameat2, p->fd, name, q->fd, target, flags) ? errno : 0;
    if (!error) {
        struct stat after{};
        if (!(flags & RENAME_EXCHANGE) && !fstatat(q->fd, target, &after, AT_SYMLINK_NOFOLLOW)) {
            if (target_known && (old_target.st_nlink == 1 || S_ISDIR(old_target.st_mode)) &&
                (after.st_dev != old_target.st_dev || after.st_ino != old_target.st_ino))
                e.retire_inode(old_target);
            if (source_known && (handled || old_source.st_nlink == 1) &&
                (after.st_dev != old_source.st_dev || after.st_ino != old_source.st_ino))
                e.retire_inode(old_source);
        }
        std::lock_guard g(e.nodes_lock);
        for (auto &[id, n] : e.nodes) {
            // Conversion installs a new inode; old source handles and aliases
            // retain the original inode, never a path to the replacement.
            if (n->retired)
                continue;
            if (n->path == oldpath || n->path.starts_with(oldpath + "/")) {
                n->path = newpath + n->path.substr(oldpath.size());
                std::lock_guard cache(n->storage->cache);
                n->storage->classified = false;
            } else if ((flags & RENAME_EXCHANGE) &&
                       (n->path == newpath || n->path.starts_with(newpath + "/"))) {
                n->path = oldpath + n->path.substr(newpath.size());
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
    if (fuse_reply_open(r, fi)) {
        auto number = d->node->ino;
        delete d;
        try {
            e.collect(number);
        } catch (...) {
        }
    }
}
static void readdir(fuse_req_t r, fuse_ino_t ino, size_t size, off_t off, fuse_file_info *fi) {
    Cred c(r);
    auto d = reinterpret_cast<Directory *>(fi->fh);
    std::unique_lock g(d->lock);
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
    int error = !used ? errno : 0;
    // RELEASEDIR can delete d as soon as the reply reaches the kernel.
    // Never leave a lock guard referring to its mutex across that reply.
    g.unlock();
    if (error)
        reply_error(r, error);
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
template <typename Signature, Signature Function, bool NoReply = false> struct Guard;
template <typename... Args, void (*Function)(fuse_req_t, Args...), bool NoReply>
struct Guard<void (*)(fuse_req_t, Args...), Function, NoReply> {
    static void call(fuse_req_t request, Args... args) noexcept {
        errors::operation = __PRETTY_FUNCTION__;
        try {
            Function(request, args...);
            return;
        } catch (const std::bad_alloc &) {
            errors::report(ENOMEM, fuse_req_ctx(request)->pid, fuse_req_ctx(request)->uid, "request allocation failed");
            if constexpr (!NoReply) {
                fuse_reply_err(request, ENOMEM);
                return;
            }
        } catch (const std::system_error &error) {
            if constexpr (!NoReply) {
                reply_error(request, error.code().value());
                return;
            }
        } catch (const std::exception &error) {
            errors::report(EIO, fuse_req_ctx(request)->pid, fuse_req_ctx(request)->uid, error.what());
            if constexpr (!NoReply) {
                fuse_reply_err(request, EIO);
                return;
            }
        } catch (...) {
            errors::report(EIO, fuse_req_ctx(request)->pid, fuse_req_ctx(request)->uid, "unknown request exception");
            if constexpr (!NoReply) {
                fuse_reply_err(request, EIO);
                return;
            }
        }
        if constexpr (NoReply)
            fuse_reply_none(request);
    }
};
static ssize_t custom_read(int fd, void *buf, size_t size, void *) {
    return ::read(fd, buf, size);
}
static ssize_t custom_write(int fd, iovec *buf, int count, void *) {
    return writev(fd, buf, count);
}
int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: engine2 BACKING POLICY FUSE_FD METRICS\n");
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
        errors::destination = getenv("YT_ENGINE_ERROR_LOG");
        Engine e(argv[1], argv[2]);
        e.fuse_fd = atoi(argv[3]);
        fuse_lowlevel_ops ops{};
        ops.init = init;
        ops.lookup = Guard<decltype(ops.lookup), lookup>::call;
        ops.forget = Guard<decltype(ops.forget), forget, true>::call;
        ops.forget_multi = Guard<decltype(ops.forget_multi), forget_multi, true>::call;
        ops.getattr = Guard<decltype(ops.getattr), getattr>::call;
        ops.setattr = Guard<decltype(ops.setattr), setattr>::call;
        ops.readlink = Guard<decltype(ops.readlink), readlink>::call;
        ops.mknod = Guard<decltype(ops.mknod), mknod>::call;
        ops.mkdir = Guard<decltype(ops.mkdir), mkdir>::call;
        ops.unlink = Guard<decltype(ops.unlink), unlink>::call;
        ops.rmdir = Guard<decltype(ops.rmdir), rmdir>::call;
        ops.symlink = Guard<decltype(ops.symlink), symlink>::call;
        ops.rename = Guard<decltype(ops.rename), rename>::call;
        ops.link = Guard<decltype(ops.link), link>::call;
        ops.open = Guard<decltype(ops.open), open_file>::call;
        ops.read = Guard<decltype(ops.read), read_file>::call;
        ops.write = Guard<decltype(ops.write), write_file>::call;
        ops.flush = Guard<decltype(ops.flush), flush>::call;
        ops.release = Guard<decltype(ops.release), release>::call;
        ops.fsync = Guard<decltype(ops.fsync), fsync>::call;
        ops.opendir = Guard<decltype(ops.opendir), opendir>::call;
        ops.readdir = Guard<decltype(ops.readdir), readdir>::call;
        ops.releasedir = Guard<decltype(ops.releasedir), releasedir>::call;
        ops.statfs = Guard<decltype(ops.statfs), statfs>::call;
        ops.getxattr = Guard<decltype(ops.getxattr), getxattr>::call;
        ops.setxattr = Guard<decltype(ops.setxattr), setxattr>::call;
        ops.removexattr = Guard<decltype(ops.removexattr), removexattr>::call;
        ops.listxattr = Guard<decltype(ops.listxattr), listxattr>::call;
        ops.create = Guard<decltype(ops.create), create>::call;
        ops.flock = Guard<decltype(ops.flock), flock>::call;
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
        if (status) errors::report(EIO, 0, 0, "FUSE session loop failed");
        return status ? 1 : 0;
    } catch (const std::exception &error) {
        errors::report(EIO, 0, 0, error.what());
        return 1;
    }
}
