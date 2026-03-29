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

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "asio2exec.hpp"
#include "receiver.hpp"
#include "scope_guard.hpp"
#include "shared_promise.hpp"
#include "stop_when.hpp"
#include "task.hpp"
#include "async_mutex.hpp"
#include "impl/buffer_wrapper.hpp"
#include "ssl/datagram_bio.hpp"
#include "detached_with_data.hpp"

#include <memory>
#include <deque>
#include <concepts>
#include <type_traits>
#include <iostream>

namespace ice::ssl::impl {

template <class Op>
concept OpenSSLOperation = std::is_nothrow_invocable_v<Op> && requires(Op &op) {
    { op.success() } -> std::convertible_to<bool>;
    { op.result() } -> std::convertible_to<int>;
    { op.error() } -> std::convertible_to<int>;
};

template <class NextLayer>
struct dtls_impl : ice::datagram_receiver,
                   std::enable_shared_from_this<dtls_impl<NextLayer>> {
    using next_layer_type = NextLayer;
    enum handshake_type { server, client };

    dtls_impl(std::shared_ptr<next_layer_type> transport,
              const ice::endpoint &remote, ::SSL *ssl)
        : ice::datagram_receiver{std::move(transport)},
          _next_layer{ice::datagram_receiver::transport<next_layer_type>()},
          _remote{remote}, _ssl{ssl} {
        if (!_ssl)
            throw std::runtime_error{"ssl == nullptr"};
        auto b = _bio.new_bio();
        ::SSL_set_bio(_ssl, b, b);
    }

    dtls_impl(const dtls_impl &) = delete;
    dtls_impl(dtls_impl &&) = delete;
    dtls_impl &operator=(const dtls_impl &) = delete;
    dtls_impl &operator=(dtls_impl &&) = delete;

    ~dtls_impl() { ::SSL_free(_ssl); }

    const auto &context() const noexcept { return _next_layer.context(); }

    auto &context() noexcept { return _next_layer.context(); }

    void close() noexcept {
        if (_closed)
            return;
        _closed = true;
        _timeout_handler_promise.set_stopped();
    }

    bool is_open() const noexcept { return !_closed && !_peer_closed; }

    auto &next_layer() noexcept { return _next_layer; }

    const auto &next_layer() const noexcept { return _next_layer; }

    const auto &remote_endpoint() const noexcept { return _remote; }

    template <class ConstBufferSequence>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send(const ConstBufferSequence &buf, auto... self);

    template <class ConstBufferSequence, class Endpoint, class... Args>
    auto async_send_to(const ConstBufferSequence &buf, const Endpoint &ep,
                       Args &&...self) {
        return async_send(buf, std::forward<Args>(self)...);
    }

    template <class MutableBufferSequence>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_receive(const MutableBufferSequence &buf, auto... self);

    template <class MutableBufferSequence, class Endpoint, class... Args>
    auto async_receive_from(const MutableBufferSequence &buf, Endpoint &source,
                            Args &&...self) {
        source = _remote;
        return async_receive(buf, std::forward<Args>(self)...);
    }

    template <class... Args>
    auto async_handshake(handshake_type type, Args &&...self);

    template <class... Args>
    auto async_shutdown(bool fast_shutdown, Args &&...self);

  private:
    struct send_op;
    struct read_op;
    struct retransmission_op;
    struct handshake_op;
    struct shutdown_op;

    bool datagram_received(io_buffer_ptr &buffer,
                           const ice::endpoint &endpoint) override;

    template <OpenSSLOperation Op>
    ice::task<std::tuple<std::error_code, std::size_t>> perform(Op op,
                                                                auto... self);

    void handle_timeout();
    ice::task<void> timeout_handler();

    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    next_layer_type &_next_layer;
    ice::endpoint _remote;
    std::vector<std::byte> _gather_buf{};
    std::deque<ice::io_buffer_ptr> _recv_q{};
    std::size_t _max_recv_q_size{64};
    ice::shared_promise<void> _recv_promise{};
    datagram_bio _bio{};
    ::SSL *_ssl;
    utils::async_mutex _ssl_mutex{};
    receiver_list_t _receivers{};
    bool _closed{false};
    bool _peer_closed{false};
    bool _handing_timeout{false};
    ice::shared_promise<void> _timeout_handler_promise{};
};

} // namespace ice::ssl::impl

#include "ssl/dtls_transport_impl.ipp"