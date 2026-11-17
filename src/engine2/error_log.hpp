#pragma once
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <sys/file.h>
#include <unistd.h>

namespace errors {
inline const char *destination = nullptr;
inline thread_local const char *operation = "startup";
inline std::mutex lock;
struct Repeat { const char *operation = nullptr; int code = 0; long long second = 0; unsigned count = 0; };
inline std::array<Repeat, 64> recent{};
inline unsigned next = 0;

// This path is used only for errors. Successful filesystem callbacks perform
// no log I/O, clock reads or locking here.
inline void report(int code, pid_t pid, uid_t uid, const char *detail) noexcept {
    try {
        std::lock_guard guard(lock);
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        Repeat *item = nullptr;
        for (auto &candidate : recent)
            if (candidate.operation == operation && candidate.code == code) { item = &candidate; break; }
        if (!item) item = &recent[next++ % recent.size()];
        if (item->operation == operation && item->code == code && now - item->second < 60) {
            item->count++;
            return;
        }
        unsigned suppressed = item->operation == operation && item->code == code ? item->count : 0;
        *item = {operation, code, now, 0};
        const char *name = strstr(operation, "Function = ");
        name = name ? name + strlen("Function = ") : operation;
        auto length = strcspn(name, ";]");
        time_t wall = time(nullptr); tm local{}; localtime_r(&wall, &local);
        char timestamp[40]; strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", &local);
        char safe[512]{};
        for (size_t i = 0; i < sizeof(safe)-1 && detail && detail[i]; i++)
            safe[i] = static_cast<unsigned char>(detail[i]) < 32 ? ' ' : detail[i];
        char line[1024];
        int bytes = snprintf(line, sizeof(line),
            "%s ERROR engine_pid=%ld client_pid=%ld uid=%u operation=%.*s errno=%d %s suppressed=%u\n",
            timestamp, static_cast<long>(getpid()), static_cast<long>(pid), uid,
            static_cast<int>(length > 200 ? 200 : length), name, code, safe, suppressed);
        if (bytes <= 0) return;
        if (bytes >= static_cast<int>(sizeof(line))) bytes = sizeof(line)-1;
        int fd = STDERR_FILENO;
        int shared_lock = -1;
        struct LogCredentials {
            uid_t previous;
            LogCredentials() : previous(setfsuid(geteuid())) {}
            ~LogCredentials() { setfsuid(previous); }
        } credentials;
        if (destination) {
            char lock_path[4096];
            snprintf(lock_path, sizeof(lock_path), "%s.lock", destination);
            shared_lock = open(lock_path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
            if (shared_lock >= 0 && ::flock(shared_lock, LOCK_EX)) {
                close(shared_lock);
                shared_lock = -1;
            }
            struct stat st{}; gid_t group = getegid();
            if (!lstat(destination, &st)) {
                group = st.st_gid;
                if (st.st_size + bytes > 1024*1024) {
                    char old[4096], newer[4096];
                    for (int i = 3; i >= 1; i--) {
                        if (i == 1) snprintf(old, sizeof(old), "%s", destination);
                        else snprintf(old, sizeof(old), "%s.%d", destination, i-1);
                        snprintf(newer, sizeof(newer), "%s.%d", destination, i);
                        rename(old, newer);
                    }
                }
            }
            fd = open(destination, O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW, 0640);
            if (fd < 0) fd = STDERR_FILENO;
            else if (geteuid() == 0) { if (fchown(fd, 0, group)) {} }
        }
        if (::write(fd, line, bytes) < 0) {}
        if (fd != STDERR_FILENO) close(fd);
        if (shared_lock >= 0) close(shared_lock);
    } catch (...) { /* Diagnostics must never take down filesystem service. */ }
}
}
