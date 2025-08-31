#pragma once

#include "config.hpp"
#include "socket_transport.hpp"
#include "impl/buffer_wrapper.hpp"

#include <boost/any/basic_any.hpp>

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
    send_to(ice::buffer_wrapper data, ice::endpoint dst) = 0;

    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(const void *data, std::size_t size, ice::endpoint dst) = 0;

    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send(ice::buffer_wrapper data) = 0;

    virtual ice::task<std::tuple<std::error_code, std::size_t>>
    send(const void *data, std::size_t size) = 0;

    virtual const void *data() const noexcept = 0;
    virtual void *data() noexcept = 0;

    virtual void connect(const ice::endpoint &endpoint) = 0;

    virtual void add_receiver(ice::receiver_base &receiver) = 0;

    virtual ice::endpoint local_endpoint() const = 0;

    virtual bool equal_to(const interface &other) const noexcept = 0;
};

template <class Transport> struct transport_impl final : public interface {
    using endpoint_type = typename Transport::endpoint_type;

    // TODO: use concept
    static constexpr bool is_datagram =
        std::is_same_v<endpoint_type, net::ip::udp::endpoint>;

    transport_impl(std::shared_ptr<Transport> transport) noexcept
        : _transport(transport) {}

    transport_impl(const transport_impl &) noexcept = default;
    transport_impl &operator=(const transport_impl &) noexcept = default;
    transport_impl(transport_impl &&) noexcept = default;
    transport_impl &operator=(transport_impl &&) noexcept = default;

    Transport *get() noexcept { return _transport.get(); }

    const Transport *get() const noexcept { return _transport.get(); }

    std::shared_ptr<Transport> get_shared() const noexcept {
        return _transport;
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(ice::buffer_wrapper data, ice::endpoint dst) override {
        auto remote = dst.convert_to<endpoint_type>();
        co_return co_await _transport->async_send_to(data, remote);
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(const void *data, std::size_t size, ice::endpoint dst) override {
        auto remote = dst.convert_to<endpoint_type>();
        co_return co_await _transport->async_send_to(
            net::const_buffer(data, size), remote);
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(ice::buffer_wrapper data) override {
        // TODO: Uses concept
        if constexpr (is_datagram) {
            co_return co_await _transport->async_send_to(data, _remote);
        } else {
            // TODO
            co_return {};
        }
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const void *data, std::size_t size) override {
        if constexpr (is_datagram) {
            co_return co_await _transport->async_send_to(
                net::const_buffer(data, size), _remote);
        } else {
            // TODO
            co_return {};
        }
    }

    const void *data() const noexcept override { return _transport.get(); }

    void *data() noexcept override { return _transport.get(); }

    void connect(const ice::endpoint &endpoint) override {
        _remote = endpoint.convert_to<endpoint_type>();
    }

    void add_receiver(ice::receiver_base &receiver) override {
        // TODO: Uses concept
        if constexpr (is_datagram) {
            auto *r = dynamic_cast<ice::datagram_receiver<endpoint_type> *>(
                &receiver);
            if (r) {
                _transport->add_receiver(*r);
            }
        } else {
        }
    }

    ice::endpoint local_endpoint() const override {
        const auto ep = _transport->local_endpoint();
        return ice::endpoint{ep.address(), ep.port()};
    }

    bool equal_to(const interface &other) const noexcept override {
        const auto *p = dynamic_cast<const transport_impl *>(&other);
        return p && p->_transport == _transport;
    }

  private:
    std::shared_ptr<Transport> _transport;
    endpoint_type _remote{};
};

} // namespace __any_transport_detail

struct any_transport {
    any_transport() noexcept = default;

    template <class Transport>
        requires(!std::is_same_v<Transport, any_transport>)
    any_transport(std::shared_ptr<Transport> transport) {
        if (!transport)
            throw std::invalid_argument("transport is null");
        _any = __any_transport_detail::transport_impl<Transport>(
            std::move(transport));
    }

    any_transport(const any_transport &) = default;
    any_transport &operator=(const any_transport &) = default;
    any_transport(any_transport &&) noexcept = default;
    any_transport &operator=(any_transport &&) noexcept = default;

    void swap(any_transport &other) noexcept { _any.swap(other._any); }

    template <class Transport>
        requires(!std::is_same_v<Transport, any_transport>)
    any_transport &operator=(std::shared_ptr<Transport> transport) {
        if (!transport)
            throw std::invalid_argument("transport is null");
        _any = __any_transport_detail::transport_impl<Transport>(
            std::move(transport));
        return *this;
    }

    const void *data() const noexcept { return get_interface()->data(); }

    void *data() noexcept { return get_interface()->data(); }

    bool empty() const noexcept { return _any.empty(); }

    operator bool() const noexcept { return !empty(); }

    void clear() noexcept { _any.clear(); }

    template <class Transport> const Transport *get() const noexcept {
        auto *impl = boost::anys::any_cast<
            const __any_transport_detail::transport_impl<Transport>>(&_any);
        if (!impl)
            return nullptr;
        return impl->get();
    }

    template <class Transport> Transport *get() noexcept {
        auto *impl = boost::anys::any_cast<
            __any_transport_detail::transport_impl<Transport>>(&_any);
        if (!impl)
            return nullptr;
        return impl->get();
    }

    template <class Transport>
    std::shared_ptr<Transport> get_shared() const noexcept {
        auto *impl = boost::anys::any_cast<
            const __any_transport_detail::transport_impl<Transport>>(&_any);
        if (!impl)
            return nullptr;
        return impl->get_shared();
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(ice::buffer_wrapper data, const ice::endpoint &dst) {
        return get_interface()->send_to(data, dst);
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send_to(const void *data, std::size_t size, const ice::endpoint &dst) {
        return get_interface()->send_to(data, size, dst);
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(ice::buffer_wrapper data) {
        return get_interface()->send(data);
    }

    ice::task<std::tuple<std::error_code, std::size_t>> send(const void *data,
                                                             std::size_t size) {
        return get_interface()->send(data, size);
    }

    template <class BufferSequence, class Endpoint>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send_to(const BufferSequence &buffers, const Endpoint &destination,
                  auto... self) {
        return get_interface()->send_to(
            buffers, ice::endpoint{destination.address(), destination.port()});
    }

    void connect(const ice::endpoint &endpoint) {
        get_interface()->connect(endpoint);
    }

    ice::endpoint local_endpoint() const {
        return get_interface()->local_endpoint();
    }

    void add_receiver(ice::receiver_base &receiver) {
        get_interface()->add_receiver(receiver);
    }

    bool equal_to(const any_transport &other) const noexcept {
        return get_interface()->equal_to(*other.get_interface());
    }

    friend bool operator==(const any_transport &lhs,
                           const any_transport &rhs) noexcept {
        return lhs.equal_to(rhs);
    }

  private:
    using udp_transport = __any_transport_detail::transport_impl<
        ice::datagram_transport<net::ip::udp::socket>>;

    __any_transport_detail::interface *get_interface() noexcept {
        return boost::anys::unsafe_any_cast<__any_transport_detail::interface>(
            &_any);
    }

    const __any_transport_detail::interface *get_interface() const noexcept {
        return boost::anys::unsafe_any_cast<__any_transport_detail::interface>(
            &_any);
    }

    boost::anys::basic_any<sizeof(udp_transport), alignof(udp_transport)> _any;
};

} // namespace ice