#pragma once

#include "config.hpp"
#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/io_context.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"
#include "receiver.hpp"
#include "scope_guard.hpp"
#include "shared_promise_v2.hpp"
#include "stop_when.hpp"
#include "task.hpp"

#include <memory>

namespace ice::impl {

template <class Socket>
struct datagram_transport_impl
    : std::enable_shared_from_this<datagram_transport_impl<Socket>> {
    using endpoint_type = typename Socket::endpoint_type;
    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    datagram_transport_impl(net::io_context &ctx, Socket &&sock) noexcept
        : _ctx(ctx), _sock(std::move(sock)),
          _local_endpoint(_sock.local_endpoint()) {}

    template <class... Args>
    datagram_transport_impl(net::io_context &ctx, Args &&...args)
        : _ctx(ctx), _sock(std::forward<Args>(args)...),
          _local_endpoint(_sock.local_endpoint()) {}

    datagram_transport_impl(const datagram_transport_impl &) = delete;
    datagram_transport_impl &
    operator=(const datagram_transport_impl &) = delete;
    datagram_transport_impl(datagram_transport_impl &&) = delete;
    datagram_transport_impl &operator=(datagram_transport_impl &&) = delete;

    void start();

    void stop() { _stop.set_value(); }

    bool is_running() const noexcept { return _running; }

    auto &socket() noexcept { return _sock; }
    const auto &socket() const noexcept { return _sock; }
    auto &context() noexcept { return _ctx; }
    const auto &context() const noexcept { return _ctx; }

    const auto &local_endpoint() const noexcept { return _local_endpoint; }

    std::size_t max_buffer_size() const noexcept { return _max_buffer_size; }
    void max_buffer_size(std::size_t size) noexcept { _max_buffer_size = size; }

    template <class ConstBufferSequence, class... Args>
    auto async_send_to(const ConstBufferSequence &buffers,
                       const endpoint_type &destination, Args &&...args) {
        return _sock.async_send_to(buffers, destination, asio2exec::use_sender);
    }

    auto &receivers() noexcept { return _receivers; }
    const auto &receivers() const noexcept { return _receivers; }

  private:
    ice::task<void> recv_loop(auto self);

    net::io_context &_ctx;
    Socket _sock;
    endpoint_type _local_endpoint;
    io_buffer_pool _pool{};
    receiver_list_t _receivers{};
    std::size_t _max_buffer_size{4096};
    bool _running{false};
    ice::shared_promise<void> _stop{};
};

} // namespace ice::impl

#include "datagram_transport_impl.ipp"