#pragma once

#include "impl/datagram_turn_client.hpp"

#include <memory>

namespace ice::turn {

constexpr bool is_channel_data(const void *data, std::size_t size) noexcept {
    return (static_cast<const uint8_t *>(data)[0] & 0xC0) == 0x40;
}

template <class NextLayer, bool IsDatagram> class client {};

template <class NextLayer> class client<NextLayer, true> {
  public:
    using impl_type = impl::datagram_client<NextLayer>;
    using next_layer_type = typename impl_type::next_layer_type;

    client(std::shared_ptr<next_layer_type> transport,
           const ice::endpoint &server, std::string username,
           std::string password)
        : _impl(std::make_shared<impl_type>(std::move(transport), server,
                                            std::move(username),
                                            std::move(password))) {}

    client(const client &) = delete;
    client &operator=(const client &) = delete;

    client(client &&) noexcept = default;

    client &operator=(client &&other) noexcept {
        if (this != &other) {
            if (_impl)
                _impl->stop();
            _impl = std::move(other._impl);
        }
        return *this;
    }

    ~client() noexcept { stop(); }

    static constexpr bool is_datagram() noexcept { return true; }

    bool is_running() const noexcept { return _impl->is_running(); }

    void stop() noexcept { _impl->stop(); }

    const auto &context() const noexcept { return _impl->context(); }
    auto &context() noexcept { return _impl->context(); }
    const auto &next_layer() const noexcept { return _impl->next_layer(); }
    auto &next_layer() noexcept { return _impl->next_layer(); }
    const auto &impl() const noexcept { return *_impl; }
    auto &impl() noexcept { return *_impl; }

    ice::endpoint local_endpoint() const noexcept {
        return _impl->local_endpoint();
    }

    ice::endpoint remote_endpoint() const noexcept {
        return _impl->remote_endpoint();
    }

    const std::string &username() const noexcept { return _impl->username(); }
    const std::string &password() const noexcept { return _impl->password(); }

    const std::optional<ice::endpoint>& relayed_address() const noexcept { return _impl->relayed_address(); }
    const std::optional<ice::endpoint>& reflex_address() const noexcept { return _impl->reflex_address(); }

    ice::task<bool> request(const stun::message &msg, ice::endpoint &from,
                            stun::message &resp, std::size_t retries,
                            auto... self) {
        return _impl->request(msg, from, resp, retries, std::move(self)...);
    }

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<ice::endpoint>> create_allocation(auto lifetime,
                                                              auto... self) {
        return _impl->create_allocation(lifetime, std::move(self)...);
    }

    uint16_t generate_channel_number() const {
        return _impl->generate_channel_number();
    }

    ice::task<bool> channel_bind(net::ip::udp::endpoint peer, uint16_t channel,
                                 auto... self) {
        return _impl->channel_bind(peer, channel, std::move(self)...);
    }

    ice::task<void> delete_allocation(auto... self) {
        return _impl->delete_allocation(std::move(self)...);
    }

    ice::task<bool> refresh(auto time_to_expiry, auto... self) {
        return _impl->refresh(time_to_expiry, std::move(self)...);
    }

    bool has_permission(const net::ip::address ip) const noexcept {
        return _impl->permissions().find(ip) != _impl->permissions().end();
    }

    ice::task<bool> create_permission(net::ip::address peer, auto... self) {
        return _impl->create_permission(peer, std::move(self)...);
    }

    ice::task<bool> create_permission(std::ranges::view auto peers,
                                      auto... self) {
        return _impl->create_permission(std::move(peers), std::move(self)...);
    }

    void delete_permission(const net::ip::address &peer) {
        _impl->delete_permission(peer);
    }

    void delete_permission(std::ranges::view auto peers) {
        _impl->delete_permission(std::move(peers));
    }

    template <class ConstBufferSequence>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send_to(const ConstBufferSequence &buffers,
                  const ice::endpoint &destination, auto... self) {
        return _impl->async_send_to(buffers, destination, std::move(self)...);
    }

    template <class ConstBufferSequence>
    auto send_channel_data(const ConstBufferSequence &buffers, uint16_t channel,
                           auto... self) {
        return _impl->send_channel_data(buffers, channel, std::move(self)...);
    }

    void add_receiver(datagram_receiver &receiver) noexcept {
        _impl->add_receiver(receiver);
    }

  private:
    std::shared_ptr<impl_type> _impl;
}; // client

} // namespace ice::turn
