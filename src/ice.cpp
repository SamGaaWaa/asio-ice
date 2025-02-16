#include "ice.hpp"
#include "address.hpp"
#include "config.hpp"
#include "scope_guard.hpp"

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/host_name.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <chrono>
#include <iostream>
#include <vector>

namespace ice {

const char *version() { return "0.1.0"; }

void get_local_addresses_test(uint64_t n) {
    int addrs_num = 0;
    auto begin = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < n; ++i) {
        addrs_num += get_local_addresses().size();
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Result: " << (addrs_num / n) << '\n'
              << "Takes: "
              << (std::chrono::duration_cast<std::chrono::nanoseconds>(end -
                                                                       begin)
                      .count() /
                  n)
              << "ns\n";
}

void debug_test() { get_local_addresses_test(1000); }

} // namespace ice