#pragma once

#include "asioice/config.hpp"
#include "asioice/detail/asio2exec.hpp"
#include "asioice/detail/receiver.hpp"
#include "asioice/detail/scope_guard.hpp"
#include "asioice/detail/shared_promise.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/early_data_cache.hpp"
#include "asioice/detail/detached_with_data.hpp"
#include "asioice/impl/transport_base.hpp"
#include "samlog.hpp"

#include <memory>

#include <boost/container/small_vector.hpp>

namespace asioice::impl {

template <class Socket>
struct datagram_transport_impl
    : std::enable_shared_from_this<datagram_transport_impl<Socket>>,
      ::asioice::transport_base {
    using socket_type = Socket;
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

    void start() override;

    void stop() noexcept override { _stop.set_value(); }

    bool is_running() const noexcept { return _running; }

    auto &socket() noexcept { return _sock; }
    const auto &socket() const noexcept { return _sock; }
    executor_type get_executor() const noexcept { return _sock.get_executor(); }
    executor_type get_executor() noexcept { return _sock.get_executor(); }

    const auto &local_endpoint() const noexcept { return _local_endpoint; }

    void add_receiver(datagram_receiver &receiver) noexcept;

    auto &receivers() noexcept { return _receivers; }
    const auto &receivers() const noexcept { return _receivers; }

    void clear_early_data() noexcept;

    template <class ConstBufferSequence>
    auto async_send(const ConstBufferSequence &buf, auto...) {
        return _sock.async_send(buf, utils::use_sender);
    }

  private:
    asioice::task<void> send_loop();
    asioice::task<void> recv_loop();
    std::error_code
    do_sendmmsg(typename ::asioice::transport_base::send_op_queue::value_type
                    &q) noexcept;

    Socket _sock;
    endpoint_type _local_endpoint;
    early_data_cache _early_data;
    bool _stop_cache_early_data{false};
    receiver_list_t _receivers{};
    bool _running{false};
    asioice::shared_promise<void> _stop{};
};

} // namespace asioice::impl

#include "asioice/impl/datagram_transport_impl.ipp"