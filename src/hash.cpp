#include "hash.hpp"

#include <openssl/rand.h>

#include <stdexcept>

namespace ice::hash {

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

void random_bytes(void *out, std::size_t size) {
    if (::RAND_bytes((unsigned char *)out, size) != 1)
        throw std::runtime_error("RAND_bytes failed");
}

} // namespace ice::hash