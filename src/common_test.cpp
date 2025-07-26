#include "config.hpp"
#include "candidate.hpp"
#include "ice.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
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

void clock_test(std::size_t n) {
    const auto begin = std::chrono::steady_clock::now();
    std::size_t total = 0;
    for (std::size_t i = 0; i < n; ++i) {
        total += (std::chrono::steady_clock::now() - begin).count();
    }
    const auto end = std::chrono::steady_clock::now();
    const auto dura =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "total: " << total << "\n, takes " << dura.count() << "ns"
              << ", avg: " << (dura.count() / n) << "ns\n";
}

int main(int argc, char **argv) {
    // ice_test();
    // candidate_test();
    clock_test(argc > 1 ? std::atoi(argv[1]) : 1000000);
}