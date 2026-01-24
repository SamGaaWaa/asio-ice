#pragma once

#include "config.hpp"
#include "address.hpp"

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

#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace ice {

struct agent_config {
    std::string username;
    std::string password;
    bool ice_controlling = true;
    bool use_loopback = false;
    bool use_ipv4 = true;
    bool use_ipv6 = false;
    std::string transport = "udp";
    std::vector<ice::endpoint> stun_servers;
    std::optional<ice::endpoint> turn_server;
    uint8_t component_count = 1;
    bool trickle_ice = true;
    std::size_t max_pending_check_count = 100;
    std::chrono::milliseconds connectivity_check_timeout{5000};
    std::chrono::milliseconds connectivity_check_interval{20};
};

} // namespace ice