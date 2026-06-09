#pragma once

#include "asioice/config.hpp"
#include "asioice/impl/sctp_impl.hpp"
#include "asioice/concepts.hpp"

namespace asioice::sctp {

template <UniqueAsyncPacketConnectionTransport Layer> struct transport {
    using next_layer_type = Layer;
    using impl_type = asioice::sctp::impl::sctp_impl<next_layer_type>;
    using executor_type = typename impl_type::executor_type;

    transport(std::shared_ptr<next_layer_type> next_layer,
              exsctp::sctp_options options = {})
        : _impl{std::make_unique<impl_type>(std::move(next_layer), options)} {}

    transport(const transport &) = delete;
    transport &operator=(const transport &) = delete;

    transport(transport &&other) noexcept : _impl{std::move(other._impl)} {}

    transport &operator=(transport &&other) noexcept {
        if (&other != this) {
            stop();
            _impl = std::move(other._impl);
        }
        return *this;
    }

    ~transport() { stop(); }

    void swap(transport &other) noexcept { std::swap(_impl, other._impl); }

    executor_type get_executor() const noexcept {
        return _impl->get_executor();
    }

    const auto &socket() const noexcept { return _impl->socket(); }

    auto &socket() noexcept { return _impl->socket(); }

    void start() { _impl->start(); }

    void stop() {
        if (_impl) {
            _impl->stop();
            _impl = nullptr;
        }
    }

    stdexec::sender_of<stdexec::set_value_t(bool)> auto
    send(const exsctp::message &msg,
         const exsctp::send_options &send_options) noexcept {
        return _impl->send(msg, send_options);
    }

    auto read() noexcept { return _impl->read(); }

    bool connected() const noexcept { return _impl->connected(); }
    auto connect() noexcept { return _impl->connect(); }

    auto accept() noexcept { return _impl->accept(); }

    bool closed() const noexcept { return _impl->closed(); }

    // Gracefully shutdowns the socket and sends all outstanding data.
    auto shutdown() noexcept { return _impl->shutdown(); }

    // Closes the connection non-gracefully. Will send ABORT if the connection
    // is not already closed.
    void close() noexcept { _impl->close(); }

    void on_outgoing_reseted(
        boost::compat::move_only_function<
            void(std::span<const dcsctp::StreamID>, bool, std::string_view)>
            cb) {
        _impl->on_outgoing_reseted(std::move(cb));
    }

    void on_incoming_reseted(boost::compat::move_only_function<
                             void(std::span<const dcsctp::StreamID>)>
                                 cb) {
        _impl->on_incoming_reseted(std::move(cb));
    }

    void on_buffered_amount_low(
        boost::compat::move_only_function<void(dcsctp::StreamID)> cb) {
        _impl->on_buffered_amount_low(std::move(cb));
    }

  private:
    std::unique_ptr<impl_type> _impl{};
};

} // namespace asioice::sctp