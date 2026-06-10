#pragma once

#include "asioice/impl/datagram_transport_impl.hpp"

namespace asioice {

template <class Socket> struct datagram_transport {
    using impl_type = impl::datagram_transport_impl<Socket>;
    using endpoint_type = typename impl_type::endpoint_type;
    using executor_type = typename impl_type::executor_type;

    datagram_transport(Socket &&sock)
        : _impl(std::make_shared<impl_type>(std::move(sock))) {}

    template <class... Args>
    datagram_transport(Args &&...args)
        : _impl(std::make_shared<impl_type>(std::forward<Args>(args)...)) {}

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
    executor_type get_executor() const noexcept {
        return _impl->get_executor();
    }
    const auto &local_endpoint() const noexcept {
        return _impl->local_endpoint();
    }

    std::size_t max_buffer_size() const noexcept {
        return _impl->max_buffer_size();
    }
    void max_buffer_size(std::size_t size) noexcept {
        _impl->max_buffer_size(size);
    }

    void set_buffer_pool(std::shared_ptr<io_buffer_pool> pool) noexcept {
        _impl->set_buffer_pool(std::move(pool));
    }

    template <class ConstBufferSequence, class... Args>
    auto async_send_to(const ConstBufferSequence &buffers,
                       const endpoint_type &destination, Args &&...args) {
        return _impl->async_send_to(buffers, destination,
                                    std::forward<Args>(args)...);
    }

    template <class ConstBufferSequence, class... Args>
    auto async_send(const ConstBufferSequence &buffers, Args &&...args) {
        return _impl->async_send(buffers, std::forward<Args>(args)...);
    }

    void add_receiver(datagram_receiver &receiver) noexcept {
        _impl->add_receiver(receiver);
    }

    void clear_early_data() noexcept { _impl->clear_early_data(); }

  private:
    std::shared_ptr<impl_type> _impl;
};

} // namespace asioice