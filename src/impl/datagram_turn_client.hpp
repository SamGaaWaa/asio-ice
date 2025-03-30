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
#include <stdexcept>

namespace ice::turn::impl {

template <class NextLayer> struct datagram_client {
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;

    datagram_client(net::io_context &ctx, next_layer_type sock,
                    const endpoint_type &server)
        : _sock(std::move(sock)), _stun_client(ctx, _sock), _server(server) {}

    datagram_client(const datagram_client &) = delete;
    datagram_client &operator=(const datagram_client &) = delete;
    datagram_client(datagram_client &&) = delete;
    datagram_client &operator=(datagram_client &&) = delete;

    void stop() noexcept {
        _sock.close();
        _stun_client.stop();
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

    bool dispatch(const void *data, std::size_t size) noexcept {
        return _stun_client.dispatch(_server, data, size);
    }

    ice::task<bool> request(const stun::message &msg, endpoint_type &from,
                            stun::message &resp, auto timeout,
                            std::size_t retries) {
        return _stun_client.request(_server, msg, from, resp, timeout, retries);
    }

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<net::ip::udp::endpoint>> allocate(auto timeout);

    ice::task<bool> channel_bind(uint16_t channel_number,
                                 net::ip::udp::endpoint peer, auto timeout);

    ice::task<bool> delete_allocation(auto timeout);

    ice::task<bool> refresh(auto time_to_expiry, auto timeout);

  private:
    next_layer_type _sock;
    stun::client<next_layer_type> _stun_client;
    endpoint_type _server;
};

} // namespace ice::turn::impl

#include "impl/datagram_turn_client.ipp"