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

enum struct transport_policy {
    ALL, RELAY
};

struct turn_credentials {
    ice::endpoint address;
    std::string username;
    std::string password;
};

struct agent_config {
    std::string username;
    std::string password;
    bool ice_controlling = true;
    bool use_loopback = false;
    bool use_ipv4 = true;
    bool use_ipv6 = false;
    std::string transport = "udp";
    std::vector<ice::endpoint> stun_servers;
    std::vector<turn_credentials> turn_servers;
    uint8_t component_count = 1;
    ice::transport_policy transport_policy = ice::transport_policy::ALL;
    bool trickle_ice = true;
    std::size_t max_pending_check_count = 100;
    std::chrono::milliseconds connectivity_check_timeout{5000};
    std::chrono::milliseconds connectivity_check_interval{20};
};

} // namespace ice