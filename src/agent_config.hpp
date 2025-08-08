#pragma once

#include "config.hpp"

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

namespace ice {

template <class StunServer = net::ip::udp::endpoint,
          class TurnServer = net::ip::udp::endpoint>
struct agent_config {
    bool ice_controlling = true;
    bool use_loopback = false;
    bool use_ipv4 = true;
    bool use_ipv6 = false;
    std::string transport = "udp";
    std::vector<StunServer> stun_servers;
    std::optional<TurnServer> turn_server;
    uint8_t component_count = 1;
};

} // namespace ice