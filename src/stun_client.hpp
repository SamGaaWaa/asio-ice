#pragma once

#include "impl/datagram_stun_client.hpp"
#include "impl/stream_stun_client.hpp"

namespace ice::stun {

template <class LowestLayer, bool IsDatagram> class client {};

template <class LowestLayer> class client<LowestLayer, true> {
    using impl_type = impl::datagram_client<LowestLayer>;

  public:
    using endpoint_type = typename impl_type::endpoint_type;

    client(net::io_context &ctx) noexcept : _impl(ctx) {}

    void stop() noexcept { _impl.stop(); }
    bool is_running() const noexcept { return _impl.is_running(); }

    const auto &context() const noexcept { return _impl.context(); }
    auto &context() noexcept { return _impl.context(); }

    bool dispatch_response(const endpoint_type &ep, const void *data,
                           std::size_t size, const void *transport) noexcept {
        return _impl.dispatch_response(ep, data, size, transport);
    }

    template <class Transport>
    ice::task<bool> request(Transport &transport, const endpoint_type &ep,
                            const stun::message &msg, endpoint_type &from,
                            stun::message &resp, std::size_t retries,
                            const void **recv_transport = nullptr) {
        return _impl.request(transport, ep, msg, from, resp, retries,
                             recv_transport);
    }

  private:
    impl_type _impl;
}; // client

template <class LowestLayer> class client<LowestLayer, false> {
    using impl_type = impl::stream_client<LowestLayer>;

  public:
    using next_layer_type = typename impl_type::next_layer_type;
    using endpoint_type = typename impl_type::endpoint_type;

    client(net::io_context &ctx, next_layer_type &sock) : _impl(ctx, sock) {}

    void stop() noexcept { _impl.stop(); }
    bool is_running() const noexcept { return _impl.is_running(); }

    const auto &context() const noexcept { return _impl.context(); }
    auto &context() noexcept { return _impl.context(); }
    const auto &next_layer() const noexcept { return _impl.next_layer(); }
    auto &next_layer() noexcept { return _impl.next_layer(); }
    const auto &local_endpoint() const noexcept {
        return _impl.local_endpoint();
    }
    const auto &remote_endpoint() const noexcept {
        return _impl.remote_endpoint();
    }

    bool dispatch(const void *data, std::size_t size) noexcept {
        return _impl.dispatch(data, size);
    }

    ice::task<bool> request(const stun::message &msg, stun::message &resp,
                            auto... self) {
        return _impl.request(msg, resp, std::move(self)...);
    }

  private:
    impl_type _impl;
}; // client

} // namespace ice::stun