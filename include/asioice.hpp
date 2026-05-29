#pragma once

#include "asioice/config.hpp"
#include "asioice/basic_agent.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/ip/udp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/ip/udp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

namespace asioice {

using agent = basic_agent<net::ip::udp::socket>;

} // namespace asioice