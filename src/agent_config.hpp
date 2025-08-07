#pragma once

#include <string>
#include <vector>

namespace ice {

struct agent_config {
    bool use_loopback = false;
    bool use_ipv6 = false;
    std::string transport = "udp";
    std::vector<std::string> stun_servers;
    std::string turn_server;
};

} // namespace ice