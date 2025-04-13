#pragma once

#include "binary.hpp"
#include "config.hpp"
#include "shared_promise_v2.hpp"
#include "stun_client.hpp"
#include "task.hpp"

#include <boost/container/small_vector.hpp>
#include <boost/intrusive/set.hpp>

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace ice::turn::impl {

template <class NextLayer>
struct datagram_client
    : std::enable_shared_from_this<datagram_client<NextLayer>> {
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;

    datagram_client(net::io_context &ctx, next_layer_type sock,
                    const endpoint_type &server, std::string username = {},
                    std::string password = {})
        : _sock(std::move(sock)), _stun_client(ctx, _sock), _server(server),
          _username(std::move(username)), _password(std::move(password)) {}

    datagram_client(const datagram_client &) = delete;
    datagram_client &operator=(const datagram_client &) = delete;
    datagram_client(datagram_client &&) = delete;
    datagram_client &operator=(datagram_client &&) = delete;

    void stop() noexcept {
        _stun_client.stop();
        _sock.close();
        _stop_refresh_task.set_value();
    }

    bool is_running() const noexcept { return _stun_client.is_running(); }

    const auto &context() const noexcept { return _stun_client.context(); }
    auto &context() noexcept { return _stun_client.context(); }
    const auto &next_layer() const noexcept { return _sock; }
    auto &next_layer() noexcept { return _sock; }

    const auto &local_endpoint() const noexcept {
        return _stun_client.local_endpoint();
    }

    const auto &remote_endpoint() const noexcept { return _server; }

    const std::string &username() const noexcept { return _username; }
    const std::string &password() const noexcept { return _password; }

    bool dispatch(const void *data, std::size_t size) noexcept {
        return _stun_client.dispatch(_server, data, size);
    }

    ice::task<bool> request(const stun::message &msg, endpoint_type &from,
                            stun::message &resp, std::size_t retries,
                            auto... self) {
        return _stun_client.request(_server, msg, from, resp, retries,
                                    std::move(self)...);
    }

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<net::ip::udp::endpoint>>
    create_allocation(auto lifetime, auto... self);

    ice::task<bool> channel_bind(uint16_t channel_number,
                                 net::ip::udp::endpoint peer, auto... self);

    ice::task<void> delete_allocation(auto... self);

    ice::task<bool> refresh(auto time_to_expiry, auto... self);

  private:
    ice::task<bool> request_with_retry(stun::message &req, stun::message &resp,
                                       std::size_t retries);
    ice::task<void> refresh_task(auto self);
    void start_refresh_task();

    next_layer_type _sock;
    stun::client<next_layer_type> _stun_client;
    endpoint_type _server;
    std::string _nonce{};
    std::string _realm{};
    const std::string _username{};
    const std::string _password{};
    std::string _hmac_key{};
    std::optional<std::array<uint8_t, stun::USERHASH_SIZE>> _userhash{};
    std::optional<stun::message::password_algorithm> _used_pwd_algo{};
    stun::message::integrity _integrity{stun::message::integrity::SHA1};
    uint32_t _lifetime{0};
    std::optional<ice::endpoint> _relayed_address{};
    std::optional<ice::endpoint> _reflex_address{};
    ice::shared_promise<void> _stop_refresh_task{};
};

} // namespace ice::turn::impl

#include "impl/datagram_turn_client.ipp"