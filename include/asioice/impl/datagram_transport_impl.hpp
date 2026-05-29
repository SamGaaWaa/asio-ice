#pragma once

#include "asioice/config.hpp"
#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#endif
#include "asio2exec.hpp"
#include "asioice/detail/receiver.hpp"
#include "asioice/detail/scope_guard.hpp"
#include "asioice/detail/shared_promise.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/early_data_cache.hpp"
#include "asioice/detail/detached_with_data.hpp"

#include <memory>

namespace asioice::impl {

template <class Socket>
struct datagram_transport_impl
    : std::enable_shared_from_this<datagram_transport_impl<Socket>> {
    using endpoint_type = typename Socket::endpoint_type;
    using executor_type = typename Socket::executor_type;
    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    datagram_transport_impl(Socket &&sock) noexcept
        : _sock(std::move(sock)), _local_endpoint(_sock.local_endpoint()),
          _early_data(16 * 1024) {}

    template <class... Args>
    datagram_transport_impl(Args &&...args)
        : _sock(std::forward<Args>(args)...),
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
    executor_type get_executor() const noexcept { return _sock.get_executor(); }
    executor_type get_executor() noexcept { return _sock.get_executor(); }

    const auto &local_endpoint() const noexcept { return _local_endpoint; }

    std::size_t max_buffer_size() const noexcept { return _max_buffer_size; }
    void max_buffer_size(std::size_t size) noexcept { _max_buffer_size = size; }

    template <class ConstBufferSequence, class... Args>
    auto async_send_to(const ConstBufferSequence &buffers,
                       const endpoint_type &destination, Args &&...args) {
        return _sock.async_send_to(buffers, destination, asio2exec::use_sender);
    }

    template <class ConstBufferSequence, class... Args>
    auto async_send(const ConstBufferSequence &buffers, Args &&...args) {
        return _sock.async_send(buffers, asio2exec::use_sender);
    }

    void add_receiver(datagram_receiver &receiver) noexcept;

    auto &receivers() noexcept { return _receivers; }
    const auto &receivers() const noexcept { return _receivers; }

    void clear_early_data() noexcept;

  private:
    asioice::task<void> recv_loop();

    Socket _sock;
    endpoint_type _local_endpoint;
    io_buffer_pool _pool{};
    early_data_cache _early_data;
    bool _stop_cache_early_data{false};
    receiver_list_t _receivers{};
    std::size_t _max_buffer_size{4096};
    bool _running{false};
    asioice::shared_promise<void> _stop{};
};

} // namespace asioice::impl

#include "asioice/impl/datagram_transport_impl.ipp"