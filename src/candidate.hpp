#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>
#include <exception>

#include "config.hpp"

#if ASIOICE_USE_BOOST > 0
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

enum struct candidate_type {
    host,
    srflx,
    prflx,
    relayed
};

std::string_view to_string(candidate_type type)noexcept;

struct candidate {
    candidate(
        std::string_view foundation,
        uint8_t component,
        std::string_view transport,
        int priority,
        net::ip::udp::endpoint address,
        candidate_type type = candidate_type::host,
        std::optional<net::ip::udp::endpoint> related = std::nullopt,
        std::string_view tcptype = "",
        std::optional<uint32_t> generation = std::nullopt
    );

    friend bool operator==(const candidate&, const candidate&)noexcept = default;

    const std::string& foundation()const noexcept {
        return _foundation;
    }

private:
    std::string _foundation;
    uint8_t _component = 0;
    std::string _transport;
    uint32_t _priority = 0;
    net::ip::udp::endpoint _address;
    candidate_type _type = candidate_type::host;
    std::optional<net::ip::udp::endpoint> _related_address;
    std::string _tcptype;
    std::optional<uint32_t> _generation;
};

static_assert(std::is_copy_constructible_v<candidate>);
static_assert(std::is_copy_assignable_v<candidate>);
static_assert(std::is_nothrow_move_constructible_v<candidate>);
static_assert(std::is_nothrow_move_assignable_v<candidate>);
static_assert(std::equality_comparable<candidate>);

std::string candidate_foundation(
	candidate_type type,
	std::string_view transport,
	const net::ip::address& base_address
);

uint32_t candidate_priority(
	uint8_t component,
	candidate_type type,
    uint32_t preference = 65535
)noexcept;

} // namespace ice