#pragma once

#include <string>
#include <vector>

namespace ice {

struct agent_config {
    std::string transport = "udp";
    ste::vector<std::string> stun_servers;
    std::string turn_server;
};

} // namespace ice