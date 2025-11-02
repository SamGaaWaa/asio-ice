#pragma once

#include "binary.hpp"
#include "config.hpp"
#include "message_pool.hpp"
#include "shared_promise_v2.hpp"
// #include "stun_client.hpp"
#include "task.hpp"

#include <boost/container/flat_map.hpp>
#include <boost/intrusive/set.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffers_iterator.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <algorithm>
#include <array>
#include <deque>
#include <expected>
#include <iostream>
#include <memory>
#include <ranges>
#include <stdexcept>

namespace ice::turn::impl {

template <class NextLayer>
struct datagram_client
    : std::enable_shared_from_this<datagram_client<NextLayer>> {
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;

    datagram_client(net::io_context &ctx, next_layer_type &sock,
                    const endpoint_type &server, ice::message_pool &pool,
                    std::string username = {}, std::string password = {})
        : _stun_client(ctx, sock), _server(server),
          _username(std::move(username)), _password(std::move(password)),
          _pool(pool) {}

    datagram_client(const datagram_client &) = delete;
    datagram_client &operator=(const datagram_client &) = delete;
    datagram_client(datagram_client &&) = delete;
    datagram_client &operator=(datagram_client &&) = delete;

    void stop() noexcept {
        if (!_is_running)
            return;
        _is_running = false;
        _stun_client.stop();
        _expired_number.clear();
        _stop_expire_number_task.set_value();
        do_delete_allocation();
        _stop_read_task.set_value();
    }

    bool is_running() const noexcept { return _is_running; }

    const auto &context() const noexcept { return _stun_client.context(); }
    auto &context() noexcept { return _stun_client.context(); }
    const auto &next_layer() const noexcept {
        return _stun_client.next_layer();
    }
    auto &next_layer() noexcept { return _stun_client.next_layer(); }

    const auto &local_endpoint() const noexcept {
        return _stun_client.local_endpoint();
    }

    const auto &remote_endpoint() const noexcept { return _server; }

    const std::string &username() const noexcept { return _username; }
    const std::string &password() const noexcept { return _password; }

    bool dispatch(const void *data, std::size_t size) noexcept {
        return _stun_client.dispatch(_server, data, size);
    }

    ice::task<bool> request(const stun::message &msg, endpoint_type &from,
                            stun::message &resp, std::size_t retries,
                            auto... self) {
        return _stun_client.request(_server, msg, from, resp, retries,
                                    std::move(self)...);
    }

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<net::ip::udp::endpoint>>
    create_allocation(auto lifetime, auto... self);

    uint16_t generate_channel_number() const;

    ice::task<bool> channel_bind(net::ip::udp::endpoint peer, uint16_t channel,
                                 auto... self);

    ice::task<void> delete_allocation(auto... self);

    ice::task<bool> refresh(auto time_to_expiry, auto... self);

    ice::task<bool> create_permission(net::ip::address peer, auto... self) {
        return create_permission(
            std::ranges::owning_view(std::array<net::ip::address, 1>{peer}),
            std::move(self)...);
    }

    ice::task<bool> create_permission(std::ranges::view auto peers,
                                      auto... self);

    void delete_permission(const net::ip::address &peer);

    void delete_permission(std::ranges::view auto peers) {
        for (const auto &peer : peers) {
            delete_permission(peer);
        }
    }

    template <class ConstBufferSequence>
    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send_to(const ConstBufferSequence &buffers,
                  const endpoint_type &destination, auto... self);

    template <class ConstBufferSequence>
    auto send_channel_data(const ConstBufferSequence &buffers, uint16_t channel,
                           auto... self);

    ice::task<std::expected<ice::message, std::error_code>>
    read(endpoint_type &from, auto... self);

    template <class MutableBufferSequence>
    auto async_receive_from(const MutableBufferSequence &buffers,
                            endpoint_type &sender_endpoint, auto... self);

  private:
    void do_delete_allocation();
    ice::task<bool> request_with_retry(stun::message &req, stun::message &resp,
                                       std::size_t retries);

    ice::task<void> refresh_allocation_task(auto self);
    void start_refresh_allocation_task();

    void clear_permissions() noexcept;

    void mark_channel_number_expired(std::ranges::view auto channel_numbers);
    ice::task<void> expire_channel_number_task(auto self);
    void start_expire_channel_number_task();

    struct permission_state : std::enable_shared_from_this<permission_state> {
        permission_state(const net::ip::address peer,
                         datagram_client<NextLayer> &client)
            : _ip(peer), _client(client.shared_from_this()) {
            _client->_ip_to_channel[_ip] = this;
        }

        permission_state(permission_state &&) = delete;
        permission_state &operator=(permission_state &&) = delete;
        permission_state(const permission_state &) = delete;
        permission_state &operator=(const permission_state &) = delete;
        ~permission_state();

        void start();
        void stop() noexcept { _stop.set_value(); }

        const net::ip::address &ip() const noexcept { return _ip; }
        std::optional<uint16_t>
        find_channel_by_port(uint16_t port) const noexcept;
        std::optional<uint16_t>
        find_port_by_channel(uint16_t channel) const noexcept;
        bool add_channel(uint16_t port, uint16_t channel) noexcept;
        bool remove_channel(uint16_t channel) noexcept;
        void remove_all_channels() noexcept;
        auto all_channels() const noexcept;
        auto all_ports() const noexcept;

      private:
        void add_to_refresh_queue(
            uint16_t channel,
            std::chrono::steady_clock::time_point refresh_time);
        std::pair<uint16_t, std::chrono::steady_clock::time_point>
        next_refresh_channel() noexcept;
        void remove_from_refresh_queue(uint16_t channel) noexcept;
        ice::task<void> refresh_permission_task(auto self);

        net::ip::address _ip{};
        boost::container::flat_map<uint16_t, uint16_t>
            _port_to_channel{}; // empty means no channel binding
        boost::container::flat_map<uint16_t, uint16_t>
            _channel_to_port{}; // empty means no channel binding
        std::shared_ptr<datagram_client<NextLayer>> _client;
        std::vector<std::pair<uint16_t, std::chrono::steady_clock::time_point>>
            _refresh_queue{};
        ice::shared_promise<void> _stop{};
    };

    struct expired_channel_number {
        uint16_t channel_number{};
        std::chrono::time_point<std::chrono::steady_clock> expiry_time{};

        friend auto operator<=>(const expired_channel_number &lhs,
                                const expired_channel_number &rhs) noexcept {
            return lhs.expiry_time <=> rhs.expiry_time;
        }
    };

    stun::client<next_layer_type> _stun_client;
    endpoint_type _server;
    std::string _nonce{};
    std::string _realm{};
    const std::string _username{};
    const std::string _password{};
    message_pool &_pool;
    std::string _hmac_key{};
    std::optional<std::array<uint8_t, stun::USERHASH_SIZE>> _userhash{};
    std::optional<stun::message::password_algorithm> _used_pwd_algo{};
    stun::message::integrity _integrity{stun::message::integrity::SHA1};
    uint32_t _lifetime{0};
    std::optional<ice::endpoint> _relayed_address{};
    std::optional<ice::endpoint> _reflex_address{};
    ice::shared_promise<void> _stop_refresh_allocation_task{};
    boost::container::flat_map<net::ip::address, permission_state *>
        _ip_to_channel{};
    boost::container::flat_map<uint16_t, permission_state *> _channel_to_ip{};
    std::deque<expired_channel_number> _expired_number{};
    ice::shared_promise<void> _stop_expire_number_task{};
    bool _is_running{true};
    ice::shared_promise<void> _stop_read_task{};
};

} // namespace ice::turn::impl

#include "impl/datagram_turn_client.ipp"