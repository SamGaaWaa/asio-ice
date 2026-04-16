#pragma once

#include "impl/datagram_turn_client.hpp"

#include <memory>

namespace asioice::turn {

constexpr bool is_channel_data(const void *data, std::size_t size) noexcept {
    return (static_cast<const uint8_t *>(data)[0] & 0xC0) == 0x40;
}

struct turn_interface {
    virtual asioice::endpoint local_endpoint() const noexcept = 0;
    virtual asioice::endpoint remote_endpoint() const noexcept = 0;
    virtual const std::string &username() const noexcept = 0;
    virtual const std::string &password() const noexcept = 0;
    virtual std::optional<asioice::endpoint>
    relayed_address() const noexcept = 0;
    virtual std::optional<asioice::endpoint>
    reflex_address() const noexcept = 0;
    virtual asioice::task<std::optional<asioice::endpoint>>
    create_allocation(std::chrono::seconds lifetime) = 0;
    virtual asioice::task<bool> channel_bind(net::ip::udp::endpoint peer) = 0;
    virtual asioice::task<void> delete_allocation() = 0;
    virtual asioice::task<bool>
    refresh(std::chrono::seconds time_to_expiry) = 0;
    virtual bool has_permission(const net::ip::address ip) const noexcept = 0;
    virtual asioice::task<bool> create_permission(net::ip::address peer) = 0;
    virtual asioice::task<bool>
    create_permission(std::span<net::ip::address> peers) = 0;
    virtual void delete_permission(const net::ip::address &peer) noexcept = 0;
    virtual void
    delete_permission(std::span<net::ip::address> peers) noexcept = 0;
};

template <class NextLayer, bool IsDatagram> class client {};

template <class NextLayer>
class client<NextLayer, true> final : public turn_interface {
  public:
    using impl_type = impl::datagram_client<NextLayer>;
    using next_layer_type = typename impl_type::next_layer_type;

    client(std::shared_ptr<next_layer_type> transport,
           const asioice::endpoint &server, std::string username,
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

    asioice::endpoint local_endpoint() const noexcept override {
        return _impl->local_endpoint();
    }

    asioice::endpoint remote_endpoint() const noexcept override {
        return _impl->remote_endpoint();
    }

    const std::string &username() const noexcept override {
        return _impl->username();
    }
    const std::string &password() const noexcept override {
        return _impl->password();
    }

    std::optional<asioice::endpoint> relayed_address() const noexcept override {
        return _impl->relayed_address();
    }
    std::optional<asioice::endpoint> reflex_address() const noexcept override {
        return _impl->reflex_address();
    }

    asioice::task<bool> request(const stun::message &msg,
                                asioice::endpoint &from, stun::message &resp,
                                std::size_t retries) {
        return _impl->request(msg, from, resp, retries);
    }

    /*
        Only support UDP between server and peer
    */
    asioice::task<std::optional<asioice::endpoint>>
    create_allocation(std::chrono::seconds lifetime) override {
        return _impl->create_allocation(lifetime);
    }

    asioice::task<bool> channel_bind(net::ip::udp::endpoint peer) override {
        return _impl->channel_bind(peer);
    }

    asioice::task<void> delete_allocation() override {
        return _impl->delete_allocation();
    }

    asioice::task<bool> refresh(std::chrono::seconds time_to_expiry) override {
        return _impl->refresh(time_to_expiry);
    }

    bool has_permission(const net::ip::address ip) const noexcept override {
        return _impl->permissions().find(ip) != _impl->permissions().end();
    }

    asioice::task<bool> create_permission(net::ip::address peer) override {
        return _impl->create_permission(peer);
    }

    asioice::task<bool>
    create_permission(std::span<net::ip::address> peers) override {
        return _impl->create_permission(peers);
    }

    void delete_permission(const net::ip::address &peer) noexcept override {
        _impl->delete_permission(peer);
    }

    void
    delete_permission(std::span<net::ip::address> peers) noexcept override {
        _impl->delete_permission(peers);
    }

    template <class ConstBufferSequence>
    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_send_to(const ConstBufferSequence &buffers,
                  const asioice::endpoint &destination, auto... self) {
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

} // namespace asioice::turn
