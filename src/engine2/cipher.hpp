#pragma once
#include "cipher_blob.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <sys/mman.h>

class Cipher301 {
    void *code_;
    std::array<unsigned char, 5280> initial_{};

  public:
    Cipher301() {
        const auto length = (sizeof(cipher_blob) + 4095) & ~size_t(4095);
        code_ = mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (code_ == MAP_FAILED)
            throw std::runtime_error("cipher allocation failed");
        std::memcpy(code_, cipher_blob, sizeof(cipher_blob));
        if (mprotect(code_, length, PROT_READ | PROT_EXEC))
            throw std::runtime_error("cipher protection failed");
        auto key = reinterpret_cast<void (*)(void *, const unsigned char *)>(
            static_cast<char *>(code_) + (0x407d1d - 0x406ffa));
        key(initial_.data(), cipher_seed);
    }
    ~Cipher301() { munmap(code_, (sizeof(cipher_blob) + 4095) & ~size_t(4095)); }
    Cipher301(const Cipher301 &) = delete;
    void apply(void *data, size_t length, uint64_t offset) const {
        struct Local {
            const Cipher301 *owner = nullptr;
            std::array<unsigned char, 5280> state;
        };
        thread_local Local local;
        if (local.owner != this) {
            local.state = initial_;
            local.owner = this;
        }
        auto transform = reinterpret_cast<void (*)(void *, void *, unsigned, long)>(
            static_cast<char *>(code_) + (0x407d5f - 0x406ffa));
        while (length) {
            unsigned n = static_cast<unsigned>(std::min(length, size_t(65536)));
            transform(local.state.data(), data, n, static_cast<long>(offset));
            length -= n;
            offset += n;
            data = static_cast<unsigned char *>(data) + n;
        }
    }
};
