#pragma once

#include "impl/datagram_turn_client.hpp"

namespace ice::turn {

using stun::is_datagram_layer;
using stun::is_stream_layer;

constexpr bool is_channel_data(const void *data, std::size_t size) noexcept {
    return (static_cast<const uint8_t *>(data)[0] & 0xC0) == 0x40;
}

template <class NextLayer> class client {};

template <is_datagram_layer NextLayer> class client<NextLayer> {
    using impl_type = impl::datagram_client<NextLayer>;

  public:
    using next_layer_type = typename impl_type::next_layer_type;
    using endpoint_type = typename impl_type::endpoint_type;

    client(net::io_context &ctx, next_layer_type sock,
           const endpoint_type &server)
        : _impl(ctx, std::move(sock), server) {}

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

    ice::task<bool> request(const stun::message &msg, endpoint_type &from,
                            stun::message &resp, auto timeout,
                            std::size_t retries) {
        return _impl.request(msg, from, resp, timeout, retries);
    }

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<net::ip::udp::endpoint>> allocate(auto timeout) {
        return _impl.allocate(timeout);
    }

    ice::task<bool> channel_bind(uint16_t channel_number,
                                 net::ip::udp::endpoint peer, auto timeout) {
        return _impl.channel_bind(channel_number, peer, timeout);
    }

    ice::task<bool> delete_allocation(auto timeout) {
        return _impl.delete_allocation(timeout);
    }

    ice::task<bool> refresh(auto time_to_expiry, auto timeout) {
        return _impl.refresh(time_to_expiry, timeout);
    }

  private:
    impl_type _impl;
}; // client

} // namespace ice::turn
