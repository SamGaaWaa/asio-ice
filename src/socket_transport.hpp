#pragma once

#include "impl/datagram_transport_impl.hpp"

namespace ice {

template <class Socket> struct datagram_transport {
    using impl_type = impl::datagram_transport_impl<Socket>;
    using endpoint_type = typename impl_type::endpoint_type;

    datagram_transport(net::io_context &ctx, Socket &&sock)
        : _impl(std::make_shared<impl_type>(ctx, std::move(sock))) {}

    template <class... Args>
    datagram_transport(net::io_context &ctx, Args &&...args)
        : _impl(std::make_shared<impl_type>(ctx, std::forward<Args>(args)...)) {
    }

    datagram_transport(const datagram_transport &) = delete;
    datagram_transport &operator=(const datagram_transport &) = delete;

    datagram_transport(datagram_transport &&other) noexcept = default;

    datagram_transport &operator=(datagram_transport &&other) noexcept {
        if (this != &other) {
            stop();
            _impl = std::move(other._impl);
        }
        return *this;
    }

    ~datagram_transport() { stop(); }

    static constexpr bool is_datagram() noexcept { return true; }

    void start() {
        if (_impl)
            _impl->start();
    }

    void stop() {
        if (_impl)
            _impl->stop();
    }

    bool is_running() const noexcept { return _impl && _impl->is_running(); }

    auto &socket() noexcept { return _impl->socket(); }
    const auto &socket() const noexcept { return _impl->socket(); }
    auto &context() noexcept { return _impl->context(); }
    const auto &context() const noexcept { return _impl->context(); }
    const auto &local_endpoint() const noexcept {
        return _impl->local_endpoint();
    }

    std::size_t max_buffer_size() const noexcept {
        return _impl->max_buffer_size();
    }
    void max_buffer_size(std::size_t size) noexcept {
        _impl->max_buffer_size(size);
    }

    template <class ConstBufferSequence, class... Args>
    auto async_send_to(const ConstBufferSequence &buffers,
                       const endpoint_type &destination, Args &&...args) {
        return _impl->async_send_to(buffers, destination,
                                    std::forward<Args>(args)...);
    }

    void add_receiver(datagram_receiver &receiver) noexcept {
        _impl->receivers().push_back(receiver);
        _impl->receivers().sort();
    }

  private:
    std::shared_ptr<impl_type> _impl;
};

} // namespace ice