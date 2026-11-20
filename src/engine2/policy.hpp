#pragma once
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fnmatch.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>

inline std::string trim(std::string s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == s.npos)
        return {};
    return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}
inline std::string basename_of(const std::string &p) {
    auto n = p.rfind('/');
    return n == p.npos ? p : p.substr(n + 1);
}
struct Identity {
    std::string executable;
    std::string basename;
    bool raw_git = false;
};

class Policy {
    struct Rule {
        std::string program, file;
    };
    std::vector<Rule> rules_;
    std::vector<std::string> excluded_directories_;
    std::vector<std::string> excluded_directory_names_;
    std::vector<std::string> monitored_extensions_;

  public:
    std::string key;
    bool encrypt_new = false;
    explicit Policy(const std::string &config, const char *exclusions = nullptr,
                    const char *extensions = nullptr, const char *excluded_names = nullptr) {
        if (exclusions) {
            std::istringstream directories(exclusions);
            for (std::string directory; std::getline(directories, directory);)
                if (directory.starts_with('/'))
                    excluded_directories_.push_back(directory == "/" ? directory : directory + '/');
        }
        if (excluded_names) {
            std::istringstream names(excluded_names);
            for (std::string name; std::getline(names, name);)
                if (!name.empty())
                    excluded_directory_names_.push_back(name);
        }
        if (extensions) {
            std::istringstream types(extensions);
            for (std::string extension; std::getline(types, extension);)
                if (extension.starts_with('.') && extension.size() > 1)
                    monitored_extensions_.push_back(extension);
        }
        std::ifstream in(config);
        if (!in)
            throw std::runtime_error("policy cannot be read");
        for (std::string line; std::getline(in, line);) {
            auto sep = line.find("==||==");
            if (sep == line.npos)
                continue;
            auto a = trim(line.substr(0, sep)), b = trim(line.substr(sep + 6));
            if (a == "encryptkey")
                key = b;
            else if (a == "new_file_mode") {
                if (b != "plain" && b != "encrypted")
                    throw std::runtime_error("invalid new file mode");
                encrypt_new = b == "encrypted";
            }
            else if (!a.empty())
                rules_.push_back({a, b});
        }
        if (key.empty() || key.size() >= 30 || key.find('\0') != key.npos)
            throw std::runtime_error("invalid policy identity");
    }
    bool excludes_directory(std::string_view path) const {
        if (std::any_of(excluded_directories_.begin(), excluded_directories_.end(),
                [&](const std::string &directory) { return path.starts_with(directory); }))
            return true;
        if (excluded_directory_names_.empty())
            return false;
        for (size_t start = 0, end; (end = path.find('/', start)) != path.npos; start = end + 1) {
            auto component = path.substr(start, end - start);
            if (std::find(excluded_directory_names_.begin(), excluded_directory_names_.end(),
                    component) != excluded_directory_names_.end())
                return true;
        }
        return false;
    }
    bool monitors_file(std::string_view path) const {
        if (excludes_directory(path) || monitored_extensions_.empty())
            return false;
        auto name = path.substr(path.find_last_of('/') + 1);
        return std::any_of(monitored_extensions_.begin(), monitored_extensions_.end(),
            [&](const std::string &extension) {
                return name.size() >= extension.size() &&
                    std::equal(extension.rbegin(), extension.rend(), name.rbegin(),
                        [](char expected, char actual) {
                            if (actual >= 'A' && actual <= 'Z')
                                actual += 'a' - 'A';
                            return expected == actual;
                        });
            });
    }
    bool encrypts_new_file(std::string_view path) const {
        return encrypt_new && monitors_file(path);
    }
    Identity identity(pid_t pid) const {
        Identity result;
        if (pid <= 0)
            return result;
        char link[4096];
        std::string proc = "/proc/" + std::to_string(pid);
        auto n = readlink((proc + "/exe").c_str(), link, sizeof(link) - 1);
        if (n < 0)
            return result;
        result.executable.assign(link, n);
        result.basename = basename_of(result.executable);
        // Names and command-line arguments are not executable identity. Pin the
        // running image to a protected system Git inode (including git-core).
        struct stat running{}, system{};
        if ((result.basename == "git" || result.basename == "git-core") &&
            !stat((proc + "/exe").c_str(), &running) &&
            S_ISREG(running.st_mode) && running.st_uid == 0 &&
            !(running.st_mode & (S_IWGRP | S_IWOTH))) {
            for (const char *git : {"/usr/bin/git", "/usr/bin/git-core", "/usr/lib/git-core/git"})
                if (!stat(git, &system) && system.st_dev == running.st_dev &&
                    system.st_ino == running.st_ino && system.st_uid == 0 &&
                    !(system.st_mode & (S_IWGRP | S_IWOTH)))
                    result.raw_git = true;
        }
        return result;
    }
    bool trusted(const Identity &id, const std::string &path) const {
        if (id.raw_git)
            return false;
        if (id.executable.empty())
            return false;
        for (auto &rule : rules_)
            if ((rule.program.find('/')==std::string::npos
                    ? !fnmatch(rule.program.c_str(),id.basename.c_str(),0)
                    : !fnmatch(rule.program.c_str(),id.executable.c_str(),0)) &&
                !fnmatch(rule.file.c_str(),path.c_str(),0))
                return true;
        return false;
    }
};
inline constexpr std::array<unsigned char, 32> MAGIC = {
    0x6e, 0x7e, 0x5a, 0x6d, 0,    0x89, 0xda, 0x16, 0xe3, 0xb3, 0x51, 0xea, 0x53, 0xaa, 0xfb, 0x8b,
    0xf6, 0x65, 0xef, 0x5a, 0xa6, 0x62, 0xa0, 0x87, 0x65, 0xf6, 0x4e, 0x62, 0x75, 0,    0x67, 0x5c};
inline int header_state(int fd, std::array<unsigned char, 1024> &head, const Policy &policy) {
    auto n = pread(fd, head.data(), 32, 0);
    if (n < 0)
        return -errno;
    if (n < 32 || memcmp(head.data(), MAGIC.data(), 32))
        return 0;
    n = pread(fd, head.data() + 32, head.size() - 32, 32);
    if (n < 0)
        return -errno;
    if (n != 992 || head[85] != 0x2d || head[86] != 1 || head[87] || head[88] ||
        memcmp(head.data() + 1019, "[END]", 5))
        return -EOPNOTSUPP;
    return memcmp(head.data() + 213, policy.key.c_str(), policy.key.size() + 1) ? -EACCES : 1;
}
