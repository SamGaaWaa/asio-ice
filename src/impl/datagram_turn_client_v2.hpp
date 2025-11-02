#pragma once

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/set.hpp>

#include "config.hpp"
#include "async_queue.hpp"
#include "binary.hpp"
#include "impl/buffer_wrapper.hpp"
#include "io_buffer.hpp"
#include "receiver.hpp"
#include "shared_promise_v2.hpp"
#include "task.hpp"
#include "stun_transaction.hpp"
#include "inplace_receiver.hpp"

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
    : ice::datagram_receiver,
      std::enable_shared_from_this<datagram_client<NextLayer>> {
    using base_type = ice::datagram_receiver;
    using next_layer_type = NextLayer;
    using buffer_sequence_type = ice::buffer_wrapper;

    datagram_client(std::shared_ptr<next_layer_type> transport,
                    const ice::endpoint &server, std::string username,
                    std::string password)
        : base_type(std::move(transport)),
          _next_layer(base_type::template transport<next_layer_type>()),
          _server(server), _username(std::move(username)),
          _password(std::move(password)) {}

    void stop() noexcept {
        if (!_is_running)
            return;
        _is_running = false;
        do_delete_allocation();
    }

    static constexpr bool is_datagram() noexcept { return true; }

    bool is_running() const noexcept { return _is_running; }

    const auto &context() const noexcept { return _next_layer.context(); }
    auto &context() noexcept { return _next_layer.context(); }

    const auto &next_layer() const noexcept { return _next_layer; }
    auto &next_layer() noexcept { return _next_layer; }

    const auto &local_endpoint() const noexcept {
        return next_layer().local_endpoint();
    }

    const auto &remote_endpoint() const noexcept { return _server; }

    auto &transaction_set() noexcept { return _transactions; }
    const auto &transaction_set() const noexcept { return _transactions; }

    const std::string &username() const noexcept { return _username; }
    const std::string &password() const noexcept { return _password; }

    ice::task<bool> request(const stun::message &msg, ice::endpoint &from,
                            stun::message &resp, std::size_t retries,
                            auto... self) noexcept;

    /*
        Only support UDP between server and peer
    */
    ice::task<std::optional<ice::endpoint>> create_allocation(auto lifetime,
                                                              auto... self);

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

    ice::task<std::tuple<std::error_code, std::size_t>>
    async_send_to(buffer_sequence_type buffers,
                  net::ip::udp::endpoint destination, auto... self);

    auto send_channel_data(buffer_sequence_type buffers, uint16_t channel,
                           auto... self);

    auto &expired_channel() noexcept { return _expired_channel; }

    const auto &expired_channel() const noexcept { return _expired_channel; }

    bool datagram_received(io_buffer_ptr &buffer,
                           const ice::endpoint &endpoint) override;

    auto &receivers() noexcept { return _receivers; }

    const auto &receivers() const noexcept { return _receivers; }

    void add_receiver(datagram_receiver &receiver) noexcept {
        receivers().push_back(receiver);
    }

  private:
    void do_delete_allocation();
    ice::task<bool> request_with_retry(stun::message &req, stun::message &resp,
                                       std::size_t retries);

    ice::task<void> refresh_allocation_task(auto self);
    void start_refresh_allocation_task();

    struct permission_state;

    struct channel_list_tag;
    using channel_list_base_hook = boost::intrusive::list_base_hook<
        boost::intrusive::tag<channel_list_tag>,
        boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;

    struct channel_to_peer_tag;
    struct peer_to_channel_tag;
    using channel_to_peer_base_hook = boost::intrusive::set_base_hook<
        boost::intrusive::tag<channel_to_peer_tag>,
        boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;
    using peer_to_channel_base_hook = boost::intrusive::set_base_hook<
        boost::intrusive::tag<peer_to_channel_tag>,
        boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;

    struct channel_state : std::enable_shared_from_this<channel_state>,
                           channel_list_base_hook,
                           channel_to_peer_base_hook,
                           peer_to_channel_base_hook {
        channel_state(std::shared_ptr<datagram_client<NextLayer>> client,
                      uint16_t channel, net::ip::udp::endpoint peer) noexcept
            : _client{std::move(client)}, _channel{channel},
              _peer{std::move(peer)} {}

        channel_state(const channel_state &) = delete;
        channel_state &operator=(const channel_state &) = delete;
        channel_state(channel_state &&) = delete;
        channel_state &operator=(channel_state &&) = delete;

        uint16_t channel() const noexcept { return _channel; }
        const auto &peer() const noexcept { return _peer; }

        struct peer_key {
            using type = net::ip::udp::endpoint;
            const type &operator()(const channel_state &ch) const noexcept {
                return ch.peer();
            }
        };

        struct channel_key {
            using type = uint16_t;
            type operator()(const channel_state &ch) const noexcept {
                return ch.channel();
            }
        };

        void
        set_permission(std::shared_ptr<permission_state> permission) noexcept {
            this->_permission = std::move(permission);
        }

        auto &client() noexcept { return *_client; }

        const auto &client() const noexcept { return *_client; }

        void start();

        void stop() noexcept {
            _state = state_t::stopped;
            remove_from_set();
            remove_from_permission();
            _stop.set_value();
        }

        void expire() noexcept {
            _state = state_t::expired;
            remove_from_set();
            remove_from_permission();
            _permission->client().expired_channel().insert(*this);
            _stop.set_value();
        }

        void remove_from_permission() noexcept {
            if (channel_list_base_hook::is_linked())
                channel_list_base_hook::unlink();
        }

        void remove_from_set() noexcept {
            if (channel_to_peer_base_hook::is_linked())
                channel_to_peer_base_hook::unlink();
            if (peer_to_channel_base_hook::is_linked())
                peer_to_channel_base_hook::unlink();
        }

      private:
        enum struct state_t : char { normal, expired, stopped };

        ice::task<void> refresh_task(auto self);

        std::shared_ptr<datagram_client<NextLayer>> _client;
        std::shared_ptr<permission_state> _permission{nullptr};
        uint16_t _channel;
        net::ip::udp::endpoint _peer;
        state_t _state{state_t::normal};
        ice::shared_promise<void> _stop{};
    };

    using channel_list_type = boost::intrusive::list<
        channel_state, boost::intrusive::base_hook<channel_list_base_hook>,
        boost::intrusive::constant_time_size<false>>;

    using channel_to_peer_type = boost::intrusive::set<
        channel_state, boost::intrusive::base_hook<channel_to_peer_base_hook>,
        boost::intrusive::key_of_value<typename channel_state::channel_key>,
        boost::intrusive::constant_time_size<false>>;
    using peer_to_channel_type = boost::intrusive::set<
        channel_state, boost::intrusive::base_hook<peer_to_channel_base_hook>,
        boost::intrusive::key_of_value<typename channel_state::peer_key>,
        boost::intrusive::constant_time_size<false>>;

    struct permission_set_tag;
    using permission_set_base_hook = boost::intrusive::set_base_hook<
        boost::intrusive::tag<permission_set_tag>,
        boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;

    struct permission_state : std::enable_shared_from_this<permission_state>,
                              permission_set_base_hook {
        permission_state(std::shared_ptr<datagram_client<NextLayer>> client,
                         const net::ip::address &ip) noexcept
            : _client(std::move(client)), _ip(ip) {}

        permission_state(const permission_state &) = delete;
        permission_state(permission_state &&) = delete;
        permission_state &operator=(const permission_state &) = delete;
        permission_state &operator=(permission_state &&) = delete;

        const net::ip::address &ip() const noexcept { return _ip; }

        auto &client() noexcept { return *_client; }

        const auto &client() const noexcept { return *_client; }

        void start();

        void stop() noexcept {
            while (!_channels.empty()) {
                _channels.front().expire();
            }
            _stop.set_value();
        }

        const auto &channels() const noexcept { return _channels; }

        auto &channels() noexcept { return _channels; }

        struct ip_key {
            using type = net::ip::address;
            const type &operator()(const permission_state &p) const noexcept {
                return p.ip();
            }
        };

      private:
        ice::task<void> refresh_task(auto self);

        std::shared_ptr<datagram_client<NextLayer>> _client;
        net::ip::address _ip;
        channel_list_type _channels;
        ice::shared_promise<void> _stop;
    };

    using permission_set_type = boost::intrusive::set<
        permission_state, boost::intrusive::base_hook<permission_set_base_hook>,
        boost::intrusive::key_of_value<typename permission_state::ip_key>,
        boost::intrusive::constant_time_size<false>>;

    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    next_layer_type &_next_layer;
    stun::transaction_set _transactions{};
    ice::endpoint _server;
    std::string _nonce{};
    std::string _realm{};
    const std::string _username{};
    const std::string _password{};
    std::string _hmac_key{};
    std::optional<std::array<uint8_t, stun::USERHASH_SIZE>> _userhash{};
    std::optional<stun::message::password_algorithm> _used_pwd_algo{};
    stun::message::integrity _integrity{stun::message::integrity::SHA1};
    uint32_t _lifetime{0};
    std::optional<ice::endpoint> _relayed_address{};
    std::optional<ice::endpoint> _reflex_address{};
    receiver_list_t _receivers;
    ice::shared_promise<void> _stop_refresh_allocation_task{};
    permission_set_type _permissions{};
    channel_to_peer_type _channel_to_peer{};
    peer_to_channel_type _peer_to_channel{};
    channel_to_peer_type _expired_channel{};
    bool _is_running{true};
};

} // namespace ice::turn::impl

#include "impl/datagram_turn_client_v2.ipp"