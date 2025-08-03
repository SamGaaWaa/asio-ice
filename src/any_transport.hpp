#pragma once

#include "config.hpp"
#include "basic_any.hpp"
#include "socket_transport.hpp"
#include "impl/buffer_wrapper.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <memory>
#include <type_traits>
#include <span>

namespace ice {

namespace __any_transport_detail {

struct interface {
    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(std::span<net::const_buffer> data, const ice::endpoint& dst, std::shared_ptr<void> self) = 0;

    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(const void *data, std::size_t size, const ice::endpoint& dst, std::shared_ptr<void> self) = 0;

    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send(std::span<net::const_buffer> data, std::shared_ptr<void> self) = 0;

    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send(const void *data, std::size_t size, std::shared_ptr<void> self) = 0;

    virtual void connect(const ice::endpoint& endpoint) = 0;

    virtual void add_receiver(ice::receiver_base& receiver) = 0;
};

template <class Transport>
struct transport_impl final : public interface {
    using endpoint_type = typename Transport::endpoint_type;
    static constexpr bool is_datagram = std::is_same_v<endpoint_type, net::ip::udp::endpoint>;

    transport_impl(std::shared_ptr<Transport> transport)noexcept : _transport(transport) {}

    transport_impl(const transport_impl&)noexcept = default;
    transport_impl& operator=(const transport_impl&)noexcept = default;
    transport_impl(transport_impl&&)noexcept = default;
    transport_impl& operator=(transport_impl&&)noexcept = default;

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(std::span<net::const_buffer> data, const ice::endpoint& dst, std::shared_ptr<void> self) override {
        co_return co_await _transport->async_send_to(data, dst.convert_to<endpoint_type>(), std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(const void *data, std::size_t size, const ice::endpoint& dst, std::shared_ptr<void> self) override {
        co_return co_await _transport->async_send_to(net::const_buffer(data, size), dst.convert_to<endpoint_type>(), std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(std::span<net::const_buffer> data, std::shared_ptr<void> self) override {
        // TODO: Uses concept
        if constexpr (is_datagram) {
            co_return co_await _transport->async_send_to(data, _remote, std::move(self));
        } else {
            // TODO
            co_return {};
        }
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const void *data, std::size_t size, std::shared_ptr<void> self) override {
        if constexpr (is_datagram) {
            co_return co_await _transport->async_send_to(net::const_buffer(data, size), _remote, std::move(self));
        } else {
            // TODO
            co_return {};
        }
    }

    void connect(const ice::endpoint& endpoint) override {
        _remote = endpoint.convert_to<endpoint_type>();
    }

    void add_receiver(ice::receiver_base& receiver) override {
        // TODO: Uses concept
        if constexpr (is_datagram) {
            auto *r = dynamic_cast<ice::datagram_receiver<endpoint_type>*>(&receiver);
            if (r) {
                _transport->add_receiver(*r);
            }
        } else {

        }

    }
private:
    std::shared_ptr<Transport> _transport;
    endpoint_type _remote{};
};

} // namespace __any_transport_detail

struct any_transport {
    template <class Transport>
    any_transport(std::shared_ptr<Transport> transport) {
        _any = __any_transport_detail::transport_impl<Transport>(std::move(transport));
    }

    any_transport(const any_transport&) = delete;
    any_transport& operator=(const any_transport&) = delete;
    any_transport(any_transport&&) noexcept = default;
    any_transport& operator=(any_transport&&) noexcept = default;

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(std::span<net::const_buffer> data, const ice::endpoint& dst, std::shared_ptr<void> self) {
        return get_interface()->send_to(data, dst, std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(const void *data, std::size_t size, const ice::endpoint& dst, std::shared_ptr<void> self) {
        return get_interface()->send_to(data, size, dst, std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(std::span<net::const_buffer> data, std::shared_ptr<void> self) {
        return get_interface()->send(data, std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const void *data, std::size_t size, std::shared_ptr<void> self) {
        return get_interface()->send(data, size, std::move(self));
    }

    template <class Endpoint>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send_to(buffer_wrapper<16> buffers,
                  const Endpoint &destination, auto... self) {
        co_return co_await send_to(std::span{buffers.buffers().data(), buffers.buffers().size()}, ice::endpoint{destination.address(), destination.port()}, nullptr);
    }
    
    void connect(const ice::endpoint& endpoint) {
        get_interface()->connect(endpoint);
    }

    void add_receiver(ice::receiver_base& receiver) {
        get_interface()->add_receiver(receiver);
    }
private:
    using udp_transport = __any_transport_detail::transport_impl<ice::datagram_transport<net::ip::udp::socket>>;

    __any_transport_detail::interface *
    get_interface() noexcept {
        return ice::unsafe_any_cast<__any_transport_detail::interface>(&_any);
    }

    const __any_transport_detail::interface *
    get_interface() const noexcept {
        return ice::unsafe_any_cast<__any_transport_detail::interface>(&_any);
    }

    ice::basic_any<sizeof(udp_transport), alignof(udp_transport)> _any;
};

} // namespace ice