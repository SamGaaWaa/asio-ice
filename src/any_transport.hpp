#pragma once

#include "config.hpp"
#include "socket_transport.hpp"
#include "impl/buffer_wrapper.hpp"
#include "concepts.hpp"

#include <boost/any/basic_any.hpp>

#include <exec/function.hpp>
#include <exec/into_tuple.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/ip/udp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <memory>
#include <type_traits>
#include <span>
#include <memory_resource>

namespace asioice {

namespace __any_transport_detail {

using allocator_query =
    exec::queries<std::pmr::polymorphic_allocator<std::byte>(
        exec::get_frame_allocator_t) noexcept>;

using sendto_result_type1 = exec::function<
    stdexec::sender_tag(asioice::buffer_wrapper data, asioice::endpoint dst),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

using sendto_result_type2 = exec::function<
    stdexec::sender_tag(const void *data, std::size_t size,
                        asioice::endpoint dst),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

using send_result_type1 = exec::function<
    stdexec::sender_tag(asioice::buffer_wrapper data),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

using send_result_type2 = exec::function<
    stdexec::sender_tag(const void *data, std::size_t size),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

struct interface {
    virtual sendto_result_type1 send_to(asioice::buffer_wrapper data,
                                        asioice::endpoint dst) = 0;

    virtual sendto_result_type2 send_to(const void *data, std::size_t size,
                                        asioice::endpoint dst) = 0;

    virtual send_result_type1 send(asioice::buffer_wrapper data) = 0;

    virtual send_result_type2 send(const void *data, std::size_t size) = 0;

    virtual const void *data() const noexcept = 0;
    virtual void *data() noexcept = 0;

    virtual const net::io_context &context() const noexcept = 0;
    virtual net::io_context &context() noexcept = 0;

    virtual void connect(const asioice::endpoint &endpoint) = 0;

    virtual void add_receiver(asioice::datagram_receiver &receiver) = 0;

    virtual void clear_early_data() noexcept = 0;

    virtual asioice::endpoint local_endpoint() const = 0;

    virtual bool equal_to(const interface &other) const noexcept = 0;
};

template <class Transport> struct transport_impl final : public interface {

    // TODO: use concept
    static constexpr bool is_datagram = Transport::is_datagram();

    transport_impl(std::shared_ptr<Transport> transport) noexcept
        : _transport(std::move(transport)) {}

    transport_impl(const transport_impl &) noexcept = default;
    transport_impl &operator=(const transport_impl &) noexcept = default;
    transport_impl(transport_impl &&) noexcept = default;
    transport_impl &operator=(transport_impl &&) noexcept = default;

    Transport *get() noexcept { return _transport.get(); }

    const Transport *get() const noexcept { return _transport.get(); }

    std::shared_ptr<Transport> get_shared() const noexcept {
        return _transport;
    }

    sendto_result_type1 send_to(asioice::buffer_wrapper data,
                                asioice::endpoint dst) override {
        return sendto_result_type1(
            std::move(data), std::move(dst),
            [this](asioice::buffer_wrapper data, asioice::endpoint dst) {
                return _transport->async_send_to(data, dst) |
                       __transform_sndr();
            });
    }

    sendto_result_type2 send_to(const void *data, std::size_t size,
                                asioice::endpoint dst) override {
        return sendto_result_type2(
            std::move(data), std::move(size), std::move(dst),
            [this](const void *data, std::size_t size, asioice::endpoint dst) {
                return _transport->async_send_to(net::const_buffer(data, size),
                                                 dst) |
                       __transform_sndr();
            });
    }

    send_result_type1 send(asioice::buffer_wrapper data) override {
        return send_result_type1(
            std::move(data), [this](asioice::buffer_wrapper data) {
                return _transport->async_send_to(data, _remote) |
                       __transform_sndr();
            });
    }

    send_result_type2 send(const void *data, std::size_t size) override {
        return send_result_type2(std::move(data), std::move(size),
                                 [this](const void *data, std::size_t size) {
                                     return _transport->async_send_to(
                                                net::const_buffer(data, size),
                                                _remote) |
                                            __transform_sndr();
                                 });
    }

    const void *data() const noexcept override { return _transport.get(); }

    void *data() noexcept override { return _transport.get(); }

    const net::io_context &context() const noexcept override {
        return _transport->context();
    }

    net::io_context &context() noexcept override {
        return _transport->context();
    }

    void connect(const asioice::endpoint &endpoint) override {
        _remote = endpoint;
    }

    void add_receiver(asioice::datagram_receiver &receiver) override {
        _transport->add_receiver(receiver);
    }

    void clear_early_data() noexcept override {
        if constexpr (requires { _transport->clear_early_data(); }) {
            _transport->clear_early_data();
        }
    }

    asioice::endpoint local_endpoint() const override {
        return _transport->local_endpoint();
    }

    bool equal_to(const interface &other) const noexcept override {
        return other.data() == data();
    }

  private:
    struct to_std_error_code {
        template <class... Args>
        static constexpr auto operator()(auto ec, Args &&...args) noexcept
            -> std::tuple<std::error_code, std::decay_t<Args>...> {
            return {std::error_code{ec}, std::forward<Args>(args)...};
        }
        template <class ErrorCode, class... Args>
        static constexpr auto
        operator()(std::tuple<ErrorCode, Args...> tup) noexcept
            -> std::tuple<std::error_code, Args...> {
            return std::apply(to_std_error_code{}, std::move(tup));
        }
    };

    static constexpr auto __transform_sndr() noexcept {
        return stdexec::then([](auto... result) noexcept {
            return to_std_error_code{}(result...);
        });
    }

    std::shared_ptr<Transport> _transport;
    asioice::endpoint _remote{};
};

} // namespace __any_transport_detail

struct any_transport {
    using allocator_type = std::pmr::polymorphic_allocator<std::byte>;

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

    const net::io_context &context() const noexcept {
        return get_interface()->context();
    }

    net::io_context &context() noexcept { return get_interface()->context(); }

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

    auto send_to(asioice::buffer_wrapper data, const asioice::endpoint &dst,
                 allocator_type alloc = {}) {
        return get_interface()->send_to(data, dst) |
               stdexec::write_env(
                   stdexec::prop(exec::get_frame_allocator, std::move(alloc)));
    }

    auto send_to(const void *data, std::size_t size,
                 const asioice::endpoint &dst, allocator_type alloc = {}) {
        return get_interface()->send_to(data, size, dst) |
               stdexec::write_env(
                   stdexec::prop(exec::get_frame_allocator, std::move(alloc)));
    }

    auto send(asioice::buffer_wrapper data, allocator_type alloc = {}) {
        return get_interface()->send(data) |
               stdexec::write_env(
                   stdexec::prop(exec::get_frame_allocator, std::move(alloc)));
    }

    auto send(const void *data, std::size_t size, allocator_type alloc = {}) {
        return get_interface()->send(data, size) |
               stdexec::write_env(
                   stdexec::prop(exec::get_frame_allocator, std::move(alloc)));
    }

    template <class BufferSequence, class Endpoint>
    auto async_send_to(const BufferSequence &buffers,
                       const Endpoint &destination, allocator_type alloc = {}) {
        return get_interface()->send_to(buffers,
                                        asioice::endpoint{destination.address(),
                                                          destination.port()}) |
               stdexec::write_env(
                   stdexec::prop(exec::get_frame_allocator, std::move(alloc)));
    }

    template <class BufferSequence>
    __any_transport_detail::send_result_type1
    async_send(const BufferSequence &buffers, allocator_type alloc = {}) {
        return get_interface()->send(buffers) |
               stdexec::write_env(
                   stdexec::prop(exec::get_frame_allocator, std::move(alloc)));
    }

    void connect(const asioice::endpoint &endpoint) {
        get_interface()->connect(endpoint);
    }

    asioice::endpoint local_endpoint() const {
        return get_interface()->local_endpoint();
    }

    void add_receiver(asioice::datagram_receiver &receiver) {
        get_interface()->add_receiver(receiver);
    }

    void clear_early_data() noexcept { get_interface()->clear_early_data(); }

    bool equal_to(const any_transport &other) const noexcept {
        return get_interface()->equal_to(*other.get_interface());
    }

    friend bool operator==(const any_transport &lhs,
                           const any_transport &rhs) noexcept {
        return lhs.equal_to(rhs);
    }

  private:
    using udp_transport = __any_transport_detail::transport_impl<
        asioice::datagram_transport<net::ip::udp::socket>>;

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

static_assert(AsyncPacketTransport<any_transport>);

} // namespace asioice