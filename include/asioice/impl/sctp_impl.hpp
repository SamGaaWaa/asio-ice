#pragma once

#include <memory>
#include <stdexcept>
#include <vector>

#include "asioice/config.hpp"
#include "asioice/concepts.hpp"
#include "asioice/detail/receiver.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/detached_with_data.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/detail/shared_promise.hpp"
#include "asioice/detail/asio2exec.hpp"
#include "exsctp/transport.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
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

namespace asioice::sctp::impl {

template <asioice::UniqueAsyncPacketConnectionTransport Layer>
struct io_interface : std::enable_shared_from_this<io_interface<Layer>> {
    using executor_type = typename Layer::executor_type;
    using scheduler_type = utils::basic_scheduler<executor_type>;

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

    void start() {
        if constexpr (requires { _next_layer->start(); }) {
            _next_layer->start();
        }
        utils::detached_with_data(
            utils::stop_when(this->read_loop(),
                             this->_stop.get_future() |
                                 stdexec::continues_on(scheduler())),
            this->shared_from_this());
    }

    void stop() noexcept {
        _ptr = nullptr;
        _on_data = nullptr;
        this->_stop.set_value();
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
                   return timer.async_wait(utils::use_sender) |
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

    void set_data_callback(void *ptr,
                           void (*on_data)(const void *data, size_t n,
                                           void *user_data)) noexcept {
        _ptr = ptr;
        _on_data = on_data;
    }

  private:
    asioice::task<void> read_loop() {
        utils::scope_guard on_exit([this]() noexcept {
            if (_on_data)
                _on_data(nullptr, 0, _ptr);
        });
        std::vector<uint8_t> buf(mtu());
        while (true) {
            auto [ec, n] = co_await _next_layer->async_receive(
                net::buffer(buf), utils::use_sender);
            if (ec) {
                ICE_IN_DEBUG {
                    std::cerr
                        << "sctp::impl::io_interface::read_loop async_receive: "
                        << ec.message() << '\n';
                }
                co_return;
            }
            if (n == 0) {
                ICE_IN_DEBUG {
                    std::cerr
                        << "sctp::impl::io_interface::read_loop: closed\n";
                }
                co_return;
            }
            if (_on_data) [[likely]]
                _on_data(buf.data(), n, _ptr);
        }
    }

    std::shared_ptr<Layer> _next_layer;
    asioice::shared_promise<void> _stop{};
    void *_ptr = nullptr;
    void (*_on_data)(const void *data, size_t n, void *user_data) = nullptr;
};

template <class Layer> struct sctp_impl {
    using next_layer_type = Layer;
    using interface_type = io_interface<next_layer_type>;
    static_assert(exsctp::IOInterface<interface_type>);
    using exsctp_transport = exsctp::basic_transport<interface_type>;
    using executor_type = typename next_layer_type::executor_type;

  private:
    static void on_data_received(const void *data, size_t n, void *user_data) {
        auto *self = static_cast<sctp_impl *>(user_data);
        if (!data) {
            self->close();
            return;
        }
        self->_transport.dispatch_packet(
            {static_cast<const uint8_t *>(data), n});
    }

  public:
    sctp_impl(std::shared_ptr<next_layer_type> next_layer,
              const exsctp::sctp_options &options) noexcept
        : _transport(std::make_shared<interface_type>(std::move(next_layer)),
                     options) {
        _transport.interface().set_data_callback(this, on_data_received);
    }

    sctp_impl(const sctp_impl &) = delete;
    sctp_impl(sctp_impl &&) = delete;
    sctp_impl &operator=(const sctp_impl &) = delete;
    sctp_impl &operator=(sctp_impl &&) = delete;

    ~sctp_impl() {}

    executor_type get_executor() const noexcept {
        return _transport.interface().get_executor();
    }

    const auto &socket() const noexcept { return _transport.socket(); }

    auto &socket() noexcept { return _transport.socket(); }

    void start() { _transport.start(); }

    void stop() { _transport.stop(); }

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

    void on_outgoing_reseted(
        boost::compat::move_only_function<
            void(std::span<const dcsctp::StreamID>, bool, std::string_view)>
            cb) {
        _transport.on_outgoing_reseted(std::move(cb));
    }

    void on_incoming_reseted(boost::compat::move_only_function<
                             void(std::span<const dcsctp::StreamID>)>
                                 cb) {
        _transport.on_incoming_reseted(std::move(cb));
    }

    void on_buffered_amount_low(
        boost::compat::move_only_function<void(dcsctp::StreamID)> cb) {
        _transport.on_buffered_amount_low(std::move(cb));
    }

  private:
    exsctp_transport _transport;
};

} // namespace asioice::sctp::impl