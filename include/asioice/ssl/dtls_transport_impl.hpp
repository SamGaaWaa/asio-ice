#pragma once

#include "asioice/config.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "asioice/concepts.hpp"
#include "asioice/detail/asio2exec.hpp"
#include "asioice/detail/receiver.hpp"
#include "asioice/detail/scope_guard.hpp"
#include "asioice/detail/shared_promise.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/async_mutex.hpp"
#include "asioice/detail/buffer_wrapper.hpp"
#include "asioice/ssl/datagram_bio.hpp"
#include "asioice/ssl/dtls_config.hpp"
#include "asioice/detail/detached_with_data.hpp"

#include <memory>
#include <deque>
#include <concepts>
#include <type_traits>
#include <tuple>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <iostream>

namespace asioice::ssl::impl {

template <class Op>
concept OpenSSLOperation = std::is_nothrow_invocable_v<Op> && requires(Op &op) {
    { op.success() } -> std::convertible_to<bool>;
    { op.result() } -> std::convertible_to<int>;
    { op.error() } -> std::convertible_to<int>;
};

template <class NextLayer>
struct dtls_impl : asioice::datagram_receiver,
                   std::enable_shared_from_this<dtls_impl<NextLayer>> {
    using next_layer_type = NextLayer;
    using executor_type = typename next_layer_type::executor_type;
    using timer_type = net::steady_timer::rebind_executor<executor_type>::other;
    enum handshake_type { server, client };

    dtls_impl(std::shared_ptr<next_layer_type> transport, dtls_certificate cert)
        : asioice::datagram_receiver{std::move(transport)},
          _next_layer{asioice::datagram_receiver::transport<next_layer_type>()},
          _cert{std::move(cert)} {
        if (!_cert)
            throw std::runtime_error{"_cert == nullptr"};
        _ssl = ::SSL_new(static_cast<::SSL_CTX *>(_cert.native_handle()));
        if (!_ssl)
            throw std::runtime_error{"ssl == nullptr"};
        auto b = _bio.new_bio();
        ::SSL_set_bio(_ssl, b, b);
        ::SSL_set_ex_data(_ssl, 0, this);
        ::SSL_set_verify(_ssl, ::SSL_get_verify_mode(_ssl),
                         &dtls_impl::verify_callback);
    }

    dtls_impl(const dtls_impl &) = delete;
    dtls_impl(dtls_impl &&) = delete;
    dtls_impl &operator=(const dtls_impl &) = delete;
    dtls_impl &operator=(dtls_impl &&) = delete;

    ~dtls_impl() { ::SSL_free(_ssl); }

    executor_type get_executor() const noexcept {
        return _next_layer.get_executor();
    }

    void close() noexcept;

    bool is_open() const noexcept { return !_closed && !_peer_closed; }

    auto &next_layer() noexcept { return _next_layer; }

    const auto &next_layer() const noexcept { return _next_layer; }

    template <class ConstBufferSequence>
    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_send(const ConstBufferSequence &buf, auto... self);

    template <class MutableBufferSequence>
    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_receive(const MutableBufferSequence &buf, auto... self);

    template <class... Args>
    auto async_handshake(handshake_type type, Args &&...self);

    template <class... Args>
    auto async_shutdown(bool fast_shutdown, Args &&...self);

    std::string get_remote_fingerprint_sha256() const;

    std::optional<srtp_key_material> export_srtp_key_material();

    void
    set_expected_remote_fingerprint(std::string fingerprint_sha256) noexcept;

  private:
    struct send_op;
    struct read_op;
    struct retransmission_op;
    struct handshake_op;
    struct shutdown_op;

    bool datagram_received(io_buffer_ptr &buffer,
                           const asioice::endpoint &endpoint) override;
    bool datagram_received(io_buffer_ptr &buffer) override;

    static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

    template <OpenSSLOperation Op>
    asioice::task<std::tuple<std::error_code, std::size_t>>
    perform(Op op, auto... self);

    void handle_timeout();
    asioice::task<void> timeout_handler();

    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    next_layer_type &_next_layer;
    dtls_certificate _cert;
    ::SSL *_ssl{nullptr};
    std::vector<std::byte> _gather_buf{};
    datagram_bio _bio{};
    utils::async_mutex _ssl_mutex{};
    receiver_list_t _receivers{};
    bool _closed{false};
    bool _peer_closed{false};
    std::string _expected_remote_fingerprint{};
    asioice::shared_promise<void> _timeout_handler_promise{};
};

} // namespace asioice::ssl::impl

#include "asioice/ssl/dtls_transport_impl.ipp"