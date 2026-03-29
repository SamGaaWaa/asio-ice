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

enum struct candidate_type { host, srflx, prflx, relay };

std::string_view type_to_string(candidate_type type) noexcept;

struct candidate {
    bool can_pair_with(const candidate &other) const noexcept;
    std::string to_string(int indent = 4) const;
    // friend bool operator==(const candidate &lhs, const candidate &rhs)
    // noexcept;
    bool operator==(const candidate &) const noexcept = delete;
    static std::optional<candidate>
    from_sdp(std::string_view sdp, std::size_t *nread = nullptr) noexcept;
    std::string to_sdp() const;

    std::string foundation;
    uint8_t component;
    std::string transport_type;
    uint32_t priority;
    ice::endpoint endpoint;
    candidate_type type;
    std::optional<ice::endpoint> related;
    std::string tcptype;
    std::optional<uint32_t> generation;
    mutable ice::any_transport transport;
};

static_assert(std::is_copy_constructible_v<candidate>);
static_assert(std::is_copy_assignable_v<candidate>);
static_assert(std::is_nothrow_move_constructible_v<candidate>);
static_assert(std::is_nothrow_move_assignable_v<candidate>);
static_assert(!std::equality_comparable<candidate>);

// bool operator==(const candidate &lhs, const candidate &rhs) noexcept;

std::string candidate_foundation(candidate_type type,
                                 std::string_view transport,
                                 const net::ip::address &base_address,
                                 std::optional<net::ip::address> server = {});

uint32_t candidate_priority(uint8_t component, candidate_type type,
                            uint32_t preference = 65535) noexcept;

} // namespace ice