#include "hash.hpp"

#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
#elif defined(__APPLE__)
    #include <unistd.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || \
      defined(__NetBSD__) || defined(__DragonFly__)
    #include <stdlib.h>
#elif defined(__linux__)
    #include <sys/random.h>
    #include <sys/errno.h>
#else
    #include <openssl/rand.h>
#endif

#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <cstring>
#include <cstdint>
#include <cstddef>

namespace asioice::hash {

void to_hex(const void *data, std::size_t size, char *out) noexcept {
    const uint8_t *begin = (const uint8_t *)data;
    const uint8_t *const end = begin + size;
    for (; begin != end; ++begin) {
        const uint8_t byte = *begin;
        *out++ = "0123456789abcdef"[byte >> 4];
        *out++ = "0123456789abcdef"[byte & 0x0f];
    }
}

std::string to_hex(const void *data, std::size_t size) {
    std::string res;
    res.resize_and_overwrite(2 * size,
                             [&](char *p, std::size_t n) -> std::size_t {
                                 to_hex(data, size, p);
                                 return 2 * size;
                             });
    return res;
}

struct random_bytes_generator {
    random_bytes_generator() noexcept = default;

    void get(uint8_t *out, std::size_t buf_size) {
        while (buf_size > 0) {
            if (!empty()) [[likely]] {
                std::size_t n = std::min(size(), buf_size);
                std::memcpy(out, &_buf[_read_idx], n);
                _read_idx += n;
                buf_size -= n;
                out += n;
                continue;
            }
            refill();
        }
    }

    std::size_t size() const noexcept {
        return _write_idx - _read_idx;
    }

    bool empty() const noexcept {
        return _write_idx == _read_idx;
    }

private:
    void refill() {
        _write_idx = 0;
        _read_idx = 0;
#if defined(_WIN32)
        NTSTATUS status = BCryptGenRandom(
            nullptr, _buf, sizeof(_buf),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0)
            throw std::system_error(
                static_cast<int>(status),
                std::system_category());
        _write_idx = sizeof(_buf);
#elif defined(__APPLE__)
        if (::getentropy(_buf, sizeof(_buf)) == -1)
            throw std::system_error(
                errno, std::generic_category());
        _write_idx = sizeof(_buf);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || \
      defined(__NetBSD__) || defined(__DragonFly__)
        ::arc4random_buf(_buf, sizeof(_buf));
        _write_idx = sizeof(_buf);
#elif defined(__linux__)
        ssize_t ret = ::getrandom(_buf, sizeof(_buf), 0);
        if (ret == -1)
            throw std::system_error(
                errno, std::generic_category());
        _write_idx = static_cast<std::size_t>(ret);
#else
        if (RAND_bytes(_buf, sizeof(_buf)) != 1)
            throw std::runtime_error("RAND_bytes failed");
        _write_idx = sizeof(_buf);
#endif
    }

    uint8_t _buf[256];
    std::size_t _read_idx{0};
    std::size_t _write_idx{0};
};

void random_bytes(void *out, std::size_t size) {
    static thread_local random_bytes_generator gen;
    gen.get(static_cast<uint8_t *>(out), size);
}

} // namespace asioice::hash