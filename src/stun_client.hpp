#pragma once

#include "impl/datagram_stun_client.hpp"
#include "impl/stream_stun_client.hpp"

namespace ice::stun {

template <class Layer>
concept is_stream_layer =
    std::is_same_v<std::remove_reference_t<Layer>, net::ip::tcp::socket>;

template <class Layer>
concept is_datagram_layer =
    std::is_same_v<std::remove_reference_t<Layer>, net::ip::udp::socket>;

static_assert(is_stream_layer<net::ip::tcp::socket>);
static_assert(is_datagram_layer<net::ip::udp::socket> &&
              !is_datagram_layer<net::ip::tcp::socket>);

template <class NextLayer> class client {};

template <is_datagram_layer NextLayer> class client<NextLayer> {
    using impl_type = impl::datagram_client<NextLayer>;

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

    bool dispatch(const endpoint_type &ep, const void *data,
                  std::size_t size) noexcept {
        return _impl.dispatch(ep, data, size);
    }

    ice::task<bool> request(const endpoint_type &ep, const stun::message &msg,
                            endpoint_type &from, stun::message &resp,
                            std::size_t retries) {
        return _impl.request(ep, msg, from, resp, retries);
    }

  private:
    impl_type _impl;
}; // client

template <is_stream_layer NextLayer> class client<NextLayer> {
    using impl_type = impl::stream_client<NextLayer>;

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