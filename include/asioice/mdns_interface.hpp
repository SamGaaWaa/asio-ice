#pragma once

#include "asioice/config.hpp"
#include "asioice/task.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/ip/address.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/ip/address.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <string>
#include <string_view>
#include <vector>
#if ASIOICE_USE_CPPMDNS
#include <memory>
#endif

#include <exec/task.hpp>

namespace asioice {

struct mdns_interface {
    virtual exec::task<net::ip::address>
    resolve(std::string_view mdns_name) = 0;
    virtual exec::task<std::string> publish(net::ip::address ip) = 0;
    virtual ~mdns_interface() {}
};

#if ASIOICE_USE_CPPMDNS
std::shared_ptr<mdns_interface> default_mdns_interface();
#endif

} // namespace asioice
