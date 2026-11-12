#pragma once
// Optional VCS process views stay outside the filesystem and cipher engine.
#include <cstring>
#include <fcntl.h>
#include <fnmatch.h>
#include <string>
#include <unistd.h>
#include <vector>
namespace ytcompat {
inline bool matches(const std::vector<std::string> &patterns, const std::string &name) {
    for (auto &pattern : patterns)
        if (!fnmatch(pattern.c_str(), name.c_str(), 0))
            return true;
    return false;
}
inline std::string basename_of(const std::string &name) {
    auto pos = name.rfind('/');
    return pos == name.npos ? name : name.substr(pos + 1);
}
inline bool raw_process(pid_t pid, const std::string &name, const std::vector<std::string> &clients,
                        const std::vector<std::string> &scripts) {
    bool raw = matches(clients, name);
    std::string proc = "/proc/" + std::to_string(pid);
    char link[4096];
    ssize_t n;
    if (!raw && !scripts.empty() && name.starts_with("python")) {
        int fd = open((proc + "/cmdline").c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return raw;
        n = read(fd, link, sizeof(link) - 1);
        close(fd);
        if (n <= 0)
            return raw;
        link[n] = 0;
        size_t at = strnlen(link, n) + 1;
        while (at < size_t(n)) {
            std::string arg = link + at;
            at += arg.size() + 1;
            if (arg.empty())
                break;
            if (arg[0] != '-') {
                raw = matches(scripts, basename_of(arg));
                break;
            }
            if (arg == "-c" || arg == "-m")
                break;
            if ((arg == "-W" || arg == "-X") && at < size_t(n))
                at += strlen(link + at) + 1;
        }
    }
    return raw;
}
} // namespace ytcompat
