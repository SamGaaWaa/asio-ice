#include "string_utils.hpp"
#include "hash2.hpp"

namespace ice::utils {

bool case_insensitive_equal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size())
        return false;
    auto it1 = a.begin();
    auto it2 = b.begin();

    while (it1 != a.end() && *it1 == *it2) {
        ++it1;
        ++it2;
    }
    if (it1 == a.end())
        return true;
    do {
        if (std::tolower(*it1) != std::tolower(*it2))
            return false;
        ++it1;
        ++it2;
    } while (it1 != a.end());
    return true;
}

std::string random_string(std::size_t n) {
    std::string res;
    if (n == 0)
        return res;
    auto hex_size = (n % 2) ? (n + 1) : n;
    res.resize_and_overwrite(hex_size, [&](char *p, std::size_t) -> std::size_t {
        unsigned char buf[64];
        char *it = p;
        const char * const end = p + hex_size; 
        while (it < end) {
            std::size_t byte_size = (end - it) / 2;
            byte_size = byte_size > sizeof(buf) ? sizeof(buf) : byte_size;
            ice::hash::random_bytes(buf, byte_size);
            ice::hash::to_hex(buf, byte_size, it);
            it += (byte_size * 2);
        }
        return n;
    });
    return res;
}

} // namespace ice::utils