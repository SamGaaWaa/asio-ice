#pragma once

#include <string>
#include <vector>

#include "config.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/ip/address.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/ip/address.hpp>
namespace ice {
namespace net = asio;
}
#endif

namespace ice {

struct endpoint {
    net::ip::address address;
    uint16_t port{0};

    friend bool operator==(const endpoint &lhs, const endpoint &rhs) noexcept {
        return lhs.address == rhs.address && lhs.port == rhs.port;
    }

    std::string to_string() const;
};

std::vector<net::ip::address> get_local_addresses();

} // namespace ice