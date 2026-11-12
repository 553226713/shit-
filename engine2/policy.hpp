#pragma once
#include "../compat/engine2_view.hpp"
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

inline std::string trim(std::string s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == s.npos)
        return {};
    return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}
inline std::vector<std::string> split(const char *text) {
    std::vector<std::string> out;
    if (!text)
        return out;
    std::string s = text;
    size_t at = 0;
    while (at < s.size()) {
        auto end = s.find(',', at);
        out.push_back(s.substr(at, end == s.npos ? end : end - at));
        if (end == s.npos)
            break;
        at = end + 1;
    }
    return out;
}
inline std::string basename_of(const std::string &p) {
    auto n = p.rfind('/');
    return n == p.npos ? p : p.substr(n + 1);
}
struct Identity {
    std::string executable;
    std::string basename;
    bool raw = false;
};

class Policy {
    struct Rule {
        std::string program, file;
    };
    std::vector<Rule> rules_;
    std::vector<std::string> excluded_ = split(getenv("YT_SCOPE_EXCLUDED_DIRS"));
    std::vector<std::string> extensions_ = split(getenv("YT_SCOPE_EXTENSIONS"));
    std::vector<std::string> names_ = split(getenv("YT_SCOPE_NAMES"));
    std::vector<std::string> raw_ = split(getenv("YT_COMPAT_RAW_CLIENTS"));
    std::vector<std::string> scripts_ = split(getenv("YT_COMPAT_SCRIPT_CLIENTS"));

  public:
    std::string key;
    explicit Policy(const std::string &config) {
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
            else if (!a.empty())
                rules_.push_back({a, b});
        }
        if (key.empty() || key.size() >= 30 || key.find('\0') != key.npos)
            throw std::runtime_error("invalid policy identity");
    }
    bool scoped(const std::string &path) const {
        size_t at = path.size() && path[0] == '/' ? 1 : 0;
        while (at < path.size()) {
            auto end = path.find('/', at);
            if (end == path.npos)
                break;
            auto part = path.substr(at, end - at);
            if (std::find(excluded_.begin(), excluded_.end(), part) != excluded_.end())
                return false;
            at = end + 1;
        }
        if (extensions_.empty())
            return true;
        auto name = path.substr(at);
        if (std::find(names_.begin(), names_.end(), name) != names_.end())
            return true;
        auto dot = name.rfind('.');
        if (dot == name.npos)
            return false;
        auto ext = name.substr(dot);
        std::transform(ext.begin(), ext.end(), ext.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return std::find(extensions_.begin(), extensions_.end(), ext) != extensions_.end();
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
        result.raw = ytcompat::raw_process(pid, result.basename, raw_, scripts_);
        return result;
    }
    bool trusted(const Identity &id, const std::string &path) const {
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
