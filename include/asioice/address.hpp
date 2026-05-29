#pragma once

#include <string>
#include <vector>
#include <variant>

#include "asioice/config.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/ip/udp.hpp>
#include <asio/ip/tcp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

namespace asioice {

struct endpoint {
    endpoint() noexcept = default;

    endpoint(const net::ip::address &addr, uint16_t port) noexcept {
        _data.emplace<0>(addr, port);
    }

    endpoint(const endpoint &) noexcept = default;
    endpoint(endpoint &&) noexcept = default;
    endpoint &operator=(const endpoint &) noexcept = default;
    endpoint &operator=(endpoint &&) noexcept = default;

    endpoint(const net::ip::udp::endpoint &e) noexcept : _data{e} {}

    endpoint(const net::ip::tcp::endpoint &e) noexcept : _data{e} {}

    endpoint &operator=(const net::ip::udp::endpoint &e) noexcept {
        _data = e;
        return *this;
    }

    endpoint &operator=(const net::ip::tcp::endpoint &e) noexcept {
        _data = e;
        return *this;
    }

    uint16_t port() const noexcept {
        return std::visit([](const auto &e) { return e.port(); }, _data);
    }

    void port(uint16_t port) noexcept {
        std::visit([port](auto &e) { e.port(port); }, _data);
    }

    net::ip::address address() const noexcept {
        return std::visit([](const auto &e) { return e.address(); }, _data);
    }

    void address(const net::ip::address &address) noexcept {
        std::visit([&address](auto &e) { e.address(address); }, _data);
    }

    operator net::ip::udp::endpoint() const noexcept {
        return net::ip::udp::endpoint{address(), port()};
    }

    operator net::ip::tcp::endpoint() const noexcept {
        return net::ip::tcp::endpoint{address(), port()};
    }

    operator net::ip::udp::endpoint &() & noexcept {
        if (_data.index() == 0) [[likely]]
            return std::get<0>(_data);
        return _data.emplace<net::ip::udp::endpoint>(address(), port());
    }

    operator net::ip::tcp::endpoint &() & noexcept {
        if (_data.index() == 1) [[unlikely]]
            return std::get<1>(_data);
        return _data.emplace<net::ip::tcp::endpoint>(address(), port());
    }

    bool operator==(const endpoint &other) const noexcept {
        return address() == other.address() && port() == other.port();
    }

    std::string to_string() const;

  private:
    std::variant<net::ip::udp::endpoint, net::ip::tcp::endpoint> _data;
};

std::vector<net::ip::address> get_local_addresses(bool use_ipv4 = true,
                                                  bool use_ipv6 = true);

} // namespace asioice