#pragma once

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
    
std::vector<net::ip::address>
get_local_addresses();

} // namespace ice