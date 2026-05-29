#pragma once

#include <memory>
#include <stdexcept>

#include "asioice/config.hpp"
#include "asioice/concepts.hpp"
#include "asioice/detail/receiver.hpp"
#include "exsctp/transport.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/steady_timer.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/steady_timer.hpp>
namespace asioice {
namespace net = asio;
}
#endif
#include "asio2exec.hpp"

namespace asioice::sctp::impl {

template <asioice::AsyncPacketConnectionTransport Layer> struct io_interface {
    using executor_type = typename Layer::executor_type;
    using scheduler_type = asio2exec::basic_scheduler<executor_type>;

    io_interface(std::shared_ptr<Layer> next_layer)
        : _next_layer{std::move(next_layer)} {
        if (!_next_layer)
            throw std::runtime_error{"_next_layer == nullptr"};
    }

    io_interface(const io_interface &) = delete;
    io_interface(io_interface &&) = delete;
    io_interface &operator=(const io_interface &) = delete;
    io_interface &operator=(io_interface &&) = delete;

    executor_type get_executor() const noexcept {
        return _next_layer->get_executor();
    }

    auto scheduler() noexcept { return scheduler_type{get_executor()}; }

    auto send(std::span<const uint8_t> data) {
        return _next_layer->async_send(data);
    }

    auto send(std::span<std::span<const uint8_t>> data_array) {
        return _next_layer->async_send(data_array);
    }

    auto schedule_at(std::chrono::steady_clock::time_point t) {
        using timer_type =
            asioice::net::steady_timer::rebind_executor<executor_type>::other;
        return stdexec::just(timer_type(this->get_executor(), t)) |
               stdexec::let_value([](auto &timer) {
                   return timer.async_wait(asio2exec::use_sender) |
                          stdexec::then([](auto ec) {}) |
                          stdexec::upon_stopped([] {});
               });
    }

    auto schedule_after(auto dura) {
        return this->schedule_at(std::chrono::steady_clock::now() + dura);
    }

    virtual std::size_t mtu() const noexcept {
        // TODO: Use next layer's MTU value
        return 1200;
    }

    void add_receiver(asioice::datagram_receiver &r) noexcept {
        _next_layer->add_receiver(r);
    }

  private:
    std::shared_ptr<Layer> _next_layer;
};

template <class Layer> struct sctp_impl final : asioice::datagram_receiver {
    using next_layer_type = Layer;
    using interface_type = io_interface<next_layer_type>;
    static_assert(exsctp::IOInterface<interface_type>);
    using exsctp_transport = exsctp::basic_transport<interface_type>;
    using executor_type = typename next_layer_type::executor_type;

    sctp_impl(std::shared_ptr<next_layer_type> next_layer,
              const exsctp::sctp_options &options) noexcept
        : _transport(std::make_shared<interface_type>(std::move(next_layer)),
                     options) {
        _transport.interface().add_receiver(*this);
    }

    executor_type get_executor() const noexcept {
        return _transport.interface().get_executor();
    }

    void start() { _transport.start(); }

    void stop() {
        // make sure datagram_received will not invoke
        detach();
        _transport.stop();
    }

    auto send(const exsctp::message &msg,
              const exsctp::send_options &send_options) noexcept {
        return _transport.send(msg, send_options);
    }

    auto read() noexcept { return _transport.read(); }

    bool connected() const noexcept { return _transport.connected(); }
    auto connect() noexcept { return _transport.connect(); }

    auto accept() noexcept { return _transport.accept(); }

    bool closed() const noexcept { return _transport.closed(); }

    // Gracefully shutdowns the socket and sends all outstanding data.
    auto shutdown() noexcept { return _transport.shutdown(); }

    // Closes the connection non-gracefully. Will send ABORT if the connection
    // is not already closed.
    void close() noexcept { _transport.close(); }

  private:
    bool datagram_received(asioice::io_buffer_ptr &buffer,
                           const asioice::endpoint &endpoint) override {
        if (!buffer || buffer->size() < 1)
            return false;
        _transport.dispatch_packet({buffer->data(), buffer->size()});
        return true;
    }

    exsctp_transport _transport;
};

} // namespace asioice::sctp::impl