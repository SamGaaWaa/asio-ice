#pragma once

#include "interface.hpp"
#include "impl/transport_impl2.hpp"
#include "option.hpp"

#include <memory>

namespace exsctp {

template <IOInterface Interface = any_io_interface> struct basic_transport {
    using interface_type = Interface;
    using impl_type = impl::transport_impl<Interface>;

    basic_transport(std::shared_ptr<interface_type> interface,
                    const exsctp::sctp_options &options)
        : _impl(std::make_shared<impl_type>(std::move(interface),
                                            dcsctp::DcSctpOptions{})) {}

    basic_transport(const basic_transport &) = delete;
    basic_transport &operator=(const basic_transport &) = delete;

    basic_transport(basic_transport &&other) noexcept
        : _impl(std::move(other._impl)) {}

    basic_transport &operator=(basic_transport &&other) noexcept {
        if (&other != this) {
            stop();
            _impl = std::exchange(other._impl, nullptr);
        }
        return *this;
    }

    ~basic_transport() { stop(); }

    void start() { _impl->start(); }

    void stop() noexcept {
        if (_impl) {
            _impl->stop();
            _impl = nullptr;
        }
    }

    void dispatch_packet(std::span<const uint8_t> data) {
        _impl->dispatch_packet(data);
    }

    exsctp::inline_task<dcsctp::SendStatus>
    send(const exsctp::message &msg, const dcsctp::SendOptions &send_options) {
        return _impl->send(msg, send_options);
    }

    auto read() noexcept { return _impl->read(); }

  private:
    std::shared_ptr<impl_type> _impl;
};

using transport = basic_transport<>;

} // namespace exsctp