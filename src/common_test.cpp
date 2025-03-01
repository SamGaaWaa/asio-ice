#include "candidate.hpp"
#include "config.hpp"
#include "ice.hpp"

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

#include <concepts>
#include <iostream>
#include <string>
#include <vector>

struct utf8_iterator {
    constexpr utf8_iterator(char *p = nullptr) noexcept : _ptr(p) {}

    constexpr char32_t operator*() const noexcept { return {}; }

  private:
    char *_ptr;
};

void ice_test() { ice::debug_test(); }

void candidate_test() { using namespace ice; }

int main() {
    ice_test();
    // candidate_test();
}