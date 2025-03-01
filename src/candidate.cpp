#include "candidate.hpp"
#include "hash.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace ice {

std::string_view to_string(candidate_type type) noexcept {
    switch (type) {
    case candidate_type::host:
        return "host";
    case candidate_type::srflx:
        return "srflx";
    case candidate_type::prflx:
        return "prflx";
    case candidate_type::relayed:
        return "relay";
    }
    return "unknown";
}

static std::string md5_hex(const std::string &key) {
    unsigned char digest[16];
    hash::MD5(digest, key);
    std::string res(16 * 2, '0');
    hash::to_hex(digest, sizeof(digest), res.data());
    return res;
}

std::string candidate_foundation(candidate_type type,
                                 std::string_view transport,
                                 const net::ip::address &base_address) {
    std::string key;
    std::string_view type_str = to_string(type);
    std::string addr_str = base_address.to_string();
    key.reserve(type_str.size() + 2 + transport.size() + addr_str.size());
    key += type_str;
    key += '|';
    key += transport;
    key += '|';
    key += addr_str;
    return md5_hex(key);
}

uint32_t candidate_priority(uint8_t component, candidate_type type,
                            uint32_t preference) noexcept {
    uint32_t type_pref = [type] {
        switch (type) {
        case candidate_type::host:
            return 126;
        case candidate_type::srflx:
            return 100;
        case candidate_type::prflx:
            return 110;
        default:
            return 0;
        }
    }();
    return (uint32_t{1} << 24) * type_pref + (uint32_t{1} << 8) * preference +
           (256 - component);
}

} // namespace ice