#include "candidate.hpp"
#include "hash.hpp"
#include "json.hpp"

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

std::string candidate::to_string(int indent) const {
    nlohmann::json j;

    j["foundation"] = this->foundation;
    j["component"] = this->component;
    j["transport"] = this->transport_type;
    j["priority"] = this->priority;
    j["endpoint"] = this->endpoint.to_string();
    j["type"] = ice::to_string(this->type);

    if (this->related) {
        j["related"] = this->related->to_string();
    }
    if (!this->tcptype.empty()) {
        j["tcptype"] = this->tcptype;
    }
    if (this->generation) {
        j["generation"] = *this->generation;
    }

    return j.dump(indent);
}

bool operator==(const candidate &lhs, const candidate &rhs) noexcept {
    return lhs.foundation == rhs.foundation && lhs.component == rhs.component &&
           std::ranges::equal(lhs.transport_type, rhs.transport_type,
                              [](char a, char b) noexcept {
                                  return std::tolower(a) == std::tolower(b);
                              }) &&
           lhs.priority == rhs.priority && lhs.endpoint == rhs.endpoint &&
           lhs.type == rhs.type && lhs.related == rhs.related &&
           std::ranges::equal(lhs.tcptype, rhs.tcptype,
                              [](char a, char b) noexcept {
                                  return std::tolower(a) == std::tolower(b);
                              }) &&
           lhs.generation == rhs.generation;
}

bool candidate::can_pair_with(const candidate &other) const noexcept {
    return this->type != ice::candidate_type::srflx &&
           this->component == other.component &&
           ((this->endpoint.address.is_v4() &&
             other.endpoint.address.is_v4()) ||
            (this->endpoint.address.is_v6() &&
             other.endpoint.address.is_v6())) &&
           std::ranges::equal(this->transport_type, other.transport_type,
                              [](char a, char b) noexcept {
                                  return std::tolower(a) == std::tolower(b);
                              });
}

} // namespace ice