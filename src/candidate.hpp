#pragma once

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>

#include "config.hpp"
#include "address.hpp"
#include "any_transport.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

namespace ice {

enum struct candidate_type { host, srflx, prflx, relayed };

std::string_view to_string(candidate_type type) noexcept;

struct candidate {
    std::string to_string() const;
    friend bool operator==(const candidate &lhs,
                           const candidate &rhs) noexcept {
        return lhs.foundation == rhs.foundation &&
               lhs.component == rhs.component &&
               lhs.transport_type == rhs.transport_type &&
               lhs.priority == rhs.priority && lhs.endpoint == rhs.endpoint &&
               lhs.type == rhs.type && lhs.related == rhs.related &&
               lhs.tcptype == rhs.tcptype && lhs.generation == rhs.generation;
    }

    std::string foundation;
    uint8_t component;
    std::string transport_type;
    uint32_t priority;
    ice::endpoint endpoint;
    candidate_type type;
    std::optional<ice::endpoint> related;
    std::string tcptype;
    std::optional<uint32_t> generation;
    ice::any_transport transport;
};

static_assert(std::is_copy_constructible_v<candidate>);
static_assert(std::is_copy_assignable_v<candidate>);
static_assert(std::is_nothrow_move_constructible_v<candidate>);
static_assert(std::is_nothrow_move_assignable_v<candidate>);
static_assert(std::equality_comparable<candidate>);

std::string candidate_foundation(candidate_type type,
                                 std::string_view transport,
                                 const net::ip::address &base_address);

uint32_t candidate_priority(uint8_t component, candidate_type type,
                            uint32_t preference = 65535) noexcept;

} // namespace ice