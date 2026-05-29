#pragma once

#include "asioice/config.hpp"
#include "asioice/detail/buffer_wrapper.hpp"
#include "asioice/concepts.hpp"
#include "asioice/detail/receiver.hpp"
#include "asioice/detail/small_buffer_resource.hpp"

#include <boost/any/basic_any.hpp>

#include <exec/function.hpp>
#include <exec/into_tuple.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/buffer.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
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
    stdexec::sender_tag(net::const_buffer data, asioice::endpoint dst),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

using sendto_result_type2 = exec::function<
    stdexec::sender_tag(std::span<const net::const_buffer> data,
                        asioice::endpoint dst),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

using send_result_type1 = exec::function<
    stdexec::sender_tag(net::const_buffer data),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

using send_result_type2 = exec::function<
    stdexec::sender_tag(std::span<const net::const_buffer> data),
    stdexec::completion_signatures<
        stdexec::set_value_t(std::tuple<std::error_code, std::size_t>),
        stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>,
    allocator_query>;

struct interface {
    virtual void start() = 0;
    virtual sendto_result_type1 send_to(net::const_buffer data,
                                        asioice::endpoint dst) = 0;

    virtual sendto_result_type2 send_to(std::span<const net::const_buffer> data,
                                        asioice::endpoint dst) = 0;

    virtual send_result_type1 send(net::const_buffer data) = 0;

    virtual send_result_type2 send(std::span<const net::const_buffer> data) = 0;

    virtual const void *data() const noexcept = 0;
    virtual void *data() noexcept = 0;

    virtual net::any_io_executor get_executor() const noexcept = 0;

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

    void start() override {
        if constexpr (requires { _transport->start(); }) {
            _transport->start();
        }
    }

    sendto_result_type1 send_to(net::const_buffer data,
                                asioice::endpoint dst) override {
        return sendto_result_type1(
            std::move(data), std::move(dst),
            [this](net::const_buffer data, asioice::endpoint dst) {
                return _transport->async_send_to(data, dst) |
                       __transform_sndr();
            });
    }

    sendto_result_type2 send_to(std::span<const net::const_buffer> data,
                                asioice::endpoint dst) override {
        return sendto_result_type2(
            std::move(data), std::move(dst),
            [this](std::span<const net::const_buffer> data,
                   asioice::endpoint dst) {
                return _transport->async_send_to(data, dst) |
                       __transform_sndr();
            });
    }

    send_result_type1 send(net::const_buffer data) override {
        return send_result_type1(
            std::move(data), [this](net::const_buffer data) {
                if constexpr (requires { _transport->async_send(data); }) {
                    return _transport->async_send(data) | __transform_sndr();
                } else {
                    return stdexec::just(std::tuple{
                        std::make_error_code(std::errc::function_not_supported),
                        std::size_t{0}});
                }
            });
    }

    send_result_type2 send(std::span<const net::const_buffer> data) override {
        return send_result_type2(
            std::move(data), [this](std::span<const net::const_buffer> data) {
                if constexpr (requires { _transport->async_send(data); }) {
                    return _transport->async_send(data) | __transform_sndr();
                } else {
                    return stdexec::just(std::tuple{
                        std::make_error_code(std::errc::function_not_supported),
                        std::size_t{0}});
                }
            });
    }

    const void *data() const noexcept override { return _transport.get(); }

    void *data() noexcept override { return _transport.get(); }

    net::any_io_executor get_executor() const noexcept override {
        return _transport->get_executor();
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
};

} // namespace __any_transport_detail

struct any_transport {
  private:
    using allocator_type = std::pmr::polymorphic_allocator<std::byte>;
    using sbo_resource_type = asioice::utils::small_buffer_resource<1024>;

    template <std::size_t Size, std::size_t Alignment>
    struct uninitialized_storage {
        uninitialized_storage() noexcept = default;

        uninitialized_storage(const uninitialized_storage &) noexcept {}
        uninitialized_storage &
        operator=(const uninitialized_storage &) noexcept {
            return *this;
        }
        uninitialized_storage(uninitialized_storage &&) noexcept {}
        uninitialized_storage &operator=(uninitialized_storage &&) noexcept {
            return *this;
        }

        std::span<std::byte> storage() noexcept {
            return std::span<std::byte>{data, Size};
        }

      private:
        alignas(Alignment) std::byte data[Size];
    };

    template <class F>
    static constexpr auto inject_sbo_resource(F &&f,
                                              allocator_type alloc) noexcept {
        return stdexec::just(
                   uninitialized_storage<sizeof(sbo_resource_type),
                                         alignof(sbo_resource_type)>{}) |
               stdexec::let_value(
                   [f = std::forward<F>(f),
                    alloc = std::move(alloc)](auto &storage) mutable {
                       return stdexec::just(
                                  sbo_resource_type::make_small_buffer_resource(
                                      storage.storage(), alloc.resource())) |
                              stdexec::let_value(
                                  [f = std::move(f)](auto &resource) mutable {
                                      return std::move(f)(resource.get());
                                  });
                   });
    }

  public:
    using executor_type = net::any_io_executor;

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

    executor_type get_executor() const noexcept {
        return get_interface()->get_executor();
    }

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

    void start() { get_interface()->start(); }

    auto send_to(net::const_buffer data, const asioice::endpoint &dst,
                 allocator_type alloc = {}) {
        return inject_sbo_resource(
            [this, data, dst](auto *resource) {
                return get_interface()->send_to(data, dst) |
                       stdexec::write_env(
                           stdexec::prop(exec::get_frame_allocator,
                                         allocator_type{resource}));
            },
            alloc);
    }

    auto send_to(std::span<const net::const_buffer> data,
                 const asioice::endpoint &dst, allocator_type alloc = {}) {
        return inject_sbo_resource(
            [this, data, dst](auto *resource) {
                return get_interface()->send_to(data, dst) |
                       stdexec::write_env(
                           stdexec::prop(exec::get_frame_allocator,
                                         allocator_type{resource}));
            },
            alloc);
    }

    template <class ConstBufferSequence>
        requires(!std::same_as<ConstBufferSequence,
                               std::span<const net::const_buffer>> &&
                 !std::same_as<ConstBufferSequence, net::const_buffer>)
    auto send_to(const ConstBufferSequence &data, const asioice::endpoint &dst,
                 allocator_type alloc = {}) {
        return stdexec::just(asioice::buffer_wrapper{data}) |
               stdexec::let_value([this, dst, alloc = std::move(alloc)](
                                      const auto &wrapper) {
                   return send_to(
                       std::span<const net::const_buffer>{wrapper.buffers()},
                       dst, std::move(alloc));
               });
    }

    auto send(net::const_buffer data, allocator_type alloc = {}) {
        return inject_sbo_resource(
            [this, data](auto *resource) {
                return get_interface()->send(data) |
                       stdexec::write_env(
                           stdexec::prop(exec::get_frame_allocator,
                                         allocator_type{resource}));
            },
            alloc);
    }

    auto send(std::span<const net::const_buffer> data,
              allocator_type alloc = {}) {
        return inject_sbo_resource(
            [this, data](auto *resource) {
                return get_interface()->send(data) |
                       stdexec::write_env(
                           stdexec::prop(exec::get_frame_allocator,
                                         allocator_type{resource}));
            },
            alloc);
    }

    template <class ConstBufferSequence>
        requires(!std::same_as<ConstBufferSequence,
                               std::span<const net::const_buffer>> &&
                 !std::same_as<ConstBufferSequence, net::const_buffer>)
    auto send(const ConstBufferSequence &data, allocator_type alloc = {}) {
        return stdexec::just(asioice::buffer_wrapper{data}) |
               stdexec::let_value([this, alloc = std::move(alloc)](
                                      const auto &wrapper) {
                   return send(
                       std::span<const net::const_buffer>{wrapper.buffers()},
                       std::move(alloc));
               });
    }

    template <class BufferSequence, class Endpoint>
    auto async_send_to(const BufferSequence &buffers,
                       const Endpoint &destination, allocator_type alloc = {}) {
        return send_to(buffers, destination, std::move(alloc));
    }

    template <class BufferSequence>
    __any_transport_detail::send_result_type1
    async_send(const BufferSequence &buffers, allocator_type alloc = {}) {
        return send(buffers, std::move(alloc));
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
    __any_transport_detail::interface *get_interface() noexcept {
        return boost::anys::unsafe_any_cast<__any_transport_detail::interface>(
            &_any);
    }

    const __any_transport_detail::interface *get_interface() const noexcept {
        return boost::anys::unsafe_any_cast<__any_transport_detail::interface>(
            &_any);
    }

    static constexpr std::size_t sbo_size = []() constexpr {
        auto align = alignof(std::max_align_t);
        return (sizeof(void *) * 3 + align - 1) / align * align;
    }();

    boost::anys::basic_any<sbo_size, alignof(std::max_align_t)> _any;
};

static_assert(AsyncPacketTransport<any_transport>);

} // namespace asioice