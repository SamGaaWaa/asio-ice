#pragma once

#include "asioice/config.hpp"
#include "asioice/address.hpp"

#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace asioice {

enum struct transport_policy { ALL, RELAY };

struct turn_credentials {
    asioice::endpoint address;
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
    std::vector<asioice::endpoint> stun_servers;
    std::vector<turn_credentials> turn_servers;
    uint8_t component_count = 1;
    asioice::transport_policy transport_policy = asioice::transport_policy::ALL;
    bool trickle_ice = true;
    std::size_t max_pending_check_count = 100;
    std::chrono::milliseconds connectivity_check_timeout{5000};
    std::chrono::milliseconds connectivity_check_interval{20};
    std::chrono::milliseconds keepalive_interval{15000};
};

} // namespace asioice