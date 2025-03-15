#pragma once

#include "binary.hpp"
#include "config.hpp"
#include "shared_promise_v2.hpp"
#include "stun_client.hpp"
#include "task.hpp"

#include <boost/circular_buffer.hpp>
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

#include "exec/task.hpp"

namespace ice::turn {

using stun::is_datagram_layer;
using stun::is_stream_layer;

constexpr bool is_channel_data(const void *data, std::size_t size) noexcept {
    return (static_cast<const uint8_t *>(data)[0] & 0xC0) == 0x40;
}

template <class NextLayer> class client_base {
  public:
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;

    client_base(net::io_context &io_context, next_layer_type sock)
        : _ctx(io_context), _sock(std::move(sock)),
          _stun_client(
              std::make_shared<stun::client<next_layer_type>>(_ctx, _sock)) {}

    client_base(const client_base &) = delete;
    client_base &operator=(const client_base &) = delete;
    client_base(client_base &&) = delete;
    client_base &operator=(client_base &&) = delete;

    const auto &context() const noexcept { return _ctx; }
    auto &context() noexcept { return _ctx; }
    const auto &socket() const noexcept { return _sock; }
    auto &socket() noexcept { return _sock; }
    const auto &local_endpoint() const noexcept {
        return _stun_client.local_endpoint();
    }
    auto &message_pool() noexcept { return _stun_client.message_pool(); }
    const auto &message_pool() const noexcept {
        return _stun_client.message_pool();
    }

  protected:
    net::io_context &_ctx;
    next_layer_type _sock;
    std::shared_ptr<stun::client<next_layer_type>> _stun_client;
};

template <class NextLayer> class client {};

template <is_datagram_layer NextLayer>
class client<NextLayer>
    : public client_base<NextLayer>,
      public std::enable_shared_from_this<client<NextLayer>> {
  public:
    using next_layer_type = typename client_base<NextLayer>::next_layer_type;
    using endpoint_type = typename client_base<NextLayer>::endpoint_type;

    client(net::io_context &_ctx, next_layer_type sock,
           const endpoint_type &server)
        : client_base<NextLayer>(_ctx, std::move(sock)), _server(server) {}

    void stop() noexcept;

    bool dispatch(std::unique_ptr<stun::message> msg);

    ice::task<std::unique_ptr<stun::message>>
    request(const stun::message &msg, auto timeout, std::size_t retries);

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<net::ip::udp::endpoint>>
    allocate(auto timeout, std::shared_ptr<client<NextLayer>> self = {});

    ice::task<bool> channel_bind(uint16_t channel_number,
                                 net::ip::udp::endpoint peer, auto timeout,
                                 std::shared_ptr<client<NextLayer>> self = {});

    ice::task<bool>
    delete_allocation(auto timeout,
                      std::shared_ptr<client<NextLayer>> self = {});

    ice::task<bool> refresh(auto time_to_expiry, auto timeout,
                            std::shared_ptr<client<NextLayer>> self = {});

  private:
    endpoint_type _server;
};

template <is_stream_layer NextLayer>
class client<NextLayer>
    : public client_base<NextLayer>,
      public std::enable_shared_from_this<client<NextLayer>> {
  public:
    using next_layer_type = typename client_base<NextLayer>::next_layer_type;
    using endpoint_type = typename client_base<NextLayer>::endpoint_type;

    client(net::io_context &_ctx, next_layer_type sock)
        : client_base<NextLayer>(_ctx, std::move(sock)) {}

    ice::task<std::unique_ptr<stun::message>> request(const stun::message &msg,
                                                      auto timeout);

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<net::ip::udp::endpoint>>
    allocate(auto timeout, std::shared_ptr<client<NextLayer>> self = {});

    ice::task<bool> channel_bind(uint16_t channel_number,
                                 net::ip::udp::endpoint peer, auto timeout,
                                 std::shared_ptr<client<NextLayer>> self = {});

    ice::task<bool>
    delete_allocation(auto timeout,
                      std::shared_ptr<client<NextLayer>> self = {});

    ice::task<bool> refresh(auto time_to_expiry, auto timeout,
                            std::shared_ptr<client<NextLayer>> self = {});
};

} // namespace ice::turn

#include "turn_client.ipp"
