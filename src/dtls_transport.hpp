#pragma once

#include "config.hpp"
#include "ssl/dtls_transport_impl.hpp"

namespace ice::ssl {

template <class NextLayer>
class dtls_transport {
public:
    using next_layer_type = NextLayer;
    using impl_type = ice::ssl::impl::dtls_impl<next_layer_type>;
    using handshake_type = impl_type::handshake_type;

    dtls_transport(std::shared_ptr<next_layer_type> transport,
        const ice::endpoint &remote,
        ::SSL *ssl):
        _impl{std::make_shared<impl_type>(std::move(transport), remote, ssl)}
    {}

    dtls_transport(const dtls_transport&) = delete;

    dtls_transport(dtls_transport&& other) noexcept:
        _impl{std::exchange(other._impl, nullptr)}
    {}

    dtls_transport& operator=(const dtls_transport&) = delete;

    dtls_transport& operator=(dtls_transport&& other) noexcept {
        if (this == &other)
            return *this;
        close();
        _impl = std::exchange(other._impl, nullptr);
        return *this;
    }

    ~dtls_transport() {
        close();
    }

    const auto& context() const noexcept {
        return _impl->context();
    }

    auto& context() noexcept {
        return _impl->context();
    }

    void close() noexcept {
        if (_impl)
            _impl->close();
    }

    bool is_open() const noexcept {
        return _impl->is_open();
    }

    auto& next_layer() noexcept {
        return _impl->next_layer();
    }

    const auto& next_layer() const noexcept {
        return _impl->next_layer();
    }

    const auto& remote_endpoint() const noexcept {
        return _impl->remote_endpoint();
    }

    template <class ConstBufferSequence, class ...Args>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send(const ConstBufferSequence& buf, Args&& ...self) {
        return _impl->async_send(buf, std::forward<Args>(self)...);
    }

    template <class ConstBufferSequence, class Endpoint, class ...Args>
    auto async_send_to(const ConstBufferSequence& buf, const Endpoint& ep, Args&& ...self) {
        return _impl->async_send_to(buf, ep, std::forward<Args>(self)...);
    }

    template <class MutableBufferSequence, class ...Args>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_receive(const MutableBufferSequence& buf, Args&& ...self) {
        return _impl->async_receive(buf, std::forward<Args>(self)...);
    }

    template <class MutableBufferSequence, class Endpoint, class ...Args>
    auto
    async_receive_from(const MutableBufferSequence& buf, Endpoint& source, Args&& ...self) {
        return _impl->async_receive_from(buf, source, std::forward<Args>(self)...);
    }

    template <class ...Args>
    auto async_handshake(handshake_type type, Args&& ...self) {
        return _impl->async_handshake(type, std::forward<Args>(self)...);
    }

    template <class ...Args>
    auto async_shutdown(bool fast_shutdown, Args&& ...self) {
        return _impl->async_shutdown(fast_shutdown, std::forward<Args>(self)...);
    }
private:
    std::shared_ptr<impl_type> _impl;
};

} // namespace ice::ssl