#pragma once

#include "asioice/config.hpp"
#include "asioice/ssl/dtls_transport_impl.hpp"

namespace asioice::ssl {

template <asioice::AsyncPacketConnectionTransport NextLayer>
class dtls_transport {
  public:
    using next_layer_type = NextLayer;
    using impl_type = asioice::ssl::impl::dtls_impl<next_layer_type>;
    using executor_type = typename impl_type::executor_type;
    using handshake_type = impl_type::handshake_type;

    dtls_transport(std::shared_ptr<next_layer_type> transport,
                   dtls_certificate cert)
        : _impl{std::make_shared<impl_type>(std::move(transport),
                                            std::move(cert))} {}

    dtls_transport(const dtls_transport &) = delete;

    dtls_transport(dtls_transport &&other) noexcept
        : _impl{std::exchange(other._impl, nullptr)} {}

    dtls_transport &operator=(const dtls_transport &) = delete;

    dtls_transport &operator=(dtls_transport &&other) noexcept {
        if (this == &other)
            return *this;
        close();
        _impl = std::exchange(other._impl, nullptr);
        return *this;
    }

    ~dtls_transport() { close(); }

    executor_type get_executor() const noexcept {
        return _impl->get_executor();
    }

    void close() noexcept {
        if (_impl)
            _impl->close();
    }

    bool is_open() const noexcept { return _impl->is_open(); }

    auto &next_layer() noexcept { return _impl->next_layer(); }

    const auto &next_layer() const noexcept { return _impl->next_layer(); }

    template <class ConstBufferSequence, class... Args>
    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_send(const ConstBufferSequence &buf, Args &&...self) {
        return _impl->async_send(buf, std::forward<Args>(self)...);
    }

    template <class MutableBufferSequence, class... Args>
    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_receive(const MutableBufferSequence &buf, Args &&...self) {
        return _impl->async_receive(buf, std::forward<Args>(self)...);
    }

    template <class... Args>
    auto async_handshake(handshake_type type, Args &&...self) {
        return _impl->async_handshake(type, std::forward<Args>(self)...);
    }

    template <class... Args>
    auto async_shutdown(bool fast_shutdown, Args &&...self) {
        return _impl->async_shutdown(fast_shutdown,
                                     std::forward<Args>(self)...);
    }

    std::string get_remote_fingerprint_sha256() const {
        return _impl->get_remote_fingerprint_sha256();
    }

    std::optional<srtp_key_material> export_srtp_key_material() {
        return _impl->export_srtp_key_material();
    }

    void set_expected_remote_fingerprint(std::string fp) noexcept {
        _impl->set_expected_remote_fingerprint(std::move(fp));
    }

  private:
    std::shared_ptr<impl_type> _impl;
};

} // namespace asioice::ssl