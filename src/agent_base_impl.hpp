#pragma once

#include "asioice/config.hpp"
#include "asioice/agent_config.hpp"
#include "asioice/impl/agent_base.hpp"
#include "asioice/address.hpp"
#include "asioice/candidate_pair.hpp"
#include "asioice/detail/stun.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/detail/stun_transaction.hpp"
#include "asioice/detail/property.hpp"
#include "asioice/detail/if_else.hpp"
#include "asioice/impl/turn_interface.hpp"

#include <exec/async_scope.hpp>
#include <exec/repeat_until.hpp>

#include <chrono>
#include <optional>
#include <vector>
#include <deque>
#include <list>
#include <memory>
#include <span>

#include <boost/intrusive/set.hpp>
#include <boost/container/flat_map.hpp>

namespace asioice {

enum struct check_list_state_t { RUNNING, COMPLETED, FAILED };

enum struct ice_server_scheme : char { stun, stuns, turn, turns };

enum struct ice_server_transport : char { udp, tcp };

struct resolved_result {
    ice_server_scheme scheme{ice_server_scheme::stun};
    std::string host{};
    uint16_t port{0};
    ice_server_transport transport{ice_server_transport::udp};
};

struct agent_base;

struct agent_base_impl : std::enable_shared_from_this<agent_base_impl> {
    agent_base_impl(net::any_io_executor ex, agent_config config,
                    agent_base *agent);

    agent_base_impl(const agent_base_impl &) = delete;
    agent_base_impl &operator=(const agent_base_impl &) = delete;
    agent_base_impl(agent_base_impl &&) = delete;
    agent_base_impl &operator=(agent_base_impl &&) = delete;

    virtual ~agent_base_impl() {}

    const auto &local_candidates() const noexcept { return _local_candidates; }
    const auto &remote_candidates() const noexcept {
        return _remote_candidates;
    }
    const auto &config() const noexcept { return _config; }
    auto &config() noexcept { return _config; }

    const auto &candidate_pairs() const noexcept { return _check_list; }

    const auto &local_username() const noexcept { return _config.username; }
    const auto &local_password() const noexcept { return _config.password; }

    const auto &remote_username() const noexcept { return _remote_username; }
    void set_remote_username(std::string username) noexcept {
        _remote_username = std::move(username);
    }
    const auto &remote_password() const noexcept { return _remote_password; }
    void set_remote_password(std::string password) noexcept {
        _remote_password = std::move(password);
    }

    void set_remote_is_lite(bool lite) noexcept {
        _remote_is_lite = lite;
        if (lite && !_config.ice_controlling)
            switch_role(true);
    }

    agent_state_t state() const noexcept { return _state; }
    auto on_state_change() noexcept {
        return _state.on_change() |
               stdexec::continues_on(utils::scheduler{_any_executor});
    }

    std::shared_ptr<io_buffer_pool> &buffer_pool() noexcept { return _pool; }

    const std::shared_ptr<io_buffer_pool> &buffer_pool() const noexcept {
        return _pool;
    }

    auto on_closed() noexcept {
        return stdexec::just() | stdexec::let_value([this] {
                   return utils::if_else(
                       stdexec::just(this->_state == agent_state_t::CLOSED),
                       [] { return stdexec::just(); },
                       [this] {
                           return this->_state.on_change() |
                                  stdexec::continues_on(
                                      utils::scheduler{this->_any_executor});
                       });
               }) |
               stdexec::then(
                   [this] { return this->_state == agent_state_t::CLOSED; }) |
               exec::repeat_until();
    }

    auto on_connected_or_closed() noexcept {
        return stdexec::just() | stdexec::let_value([this] {
                   return utils::if_else(
                       stdexec::just(this->_state == agent_state_t::CONNECTED ||
                                     this->_state == agent_state_t::CLOSED),
                       [] { return stdexec::just(); },
                       [this] {
                           return this->_state.on_change() |
                                  stdexec::continues_on(
                                      utils::scheduler{this->_any_executor});
                       });
               }) |
               stdexec::then([this] {
                   return this->_state == agent_state_t::CONNECTED ||
                          this->_state == agent_state_t::CLOSED;
               }) |
               exec::repeat_until();
    }

    check_list_state_t check_list_state() const noexcept {
        return _check_list_state;
    }

    bool restart(std::string new_ufrag, std::string new_pwd) noexcept;

    void close() noexcept;

    bool all_components_nominated() const noexcept;
    bool all_components_have_valid_pair() const noexcept;

    auto gather_candidates() {
        return utils::stop_when(this->do_gather_candidates(),
                                this->on_connected_or_closed());
    }

    asioice::task<bool> add_remote_candidate(asioice::candidate c);
    auto add_remote_candidate() noexcept {
        this->_remote_candidates_end = true;
        return stdexec::just(true);
    }

    auto connect(auto... self) noexcept {
        return utils::stop_when(this->do_connect(std::move(self)...),
                                this->on_closed());
    }

    boost::container::small_vector<asioice::candidate_pair *, 2>
    nominated_pairs() const;

    void on_local_candidates(boost::compat::move_only_function<
                             void(std::span<const asioice::candidate>)>
                                 cb) {
        _on_local_candidates = std::move(cb);
    }

    void on_data(boost::compat::move_only_function<
                 void(asioice::io_buffer_ptr &, uint8_t)>
                     callback) {
        _on_data = std::move(callback);
    }

    std::shared_ptr<asioice::candidate_pair>
    find_nominated_pair(uint8_t component) const noexcept;

    void add_receiver(ice_receiver &receiver) {
        _receivers.push_back(&receiver);
    }

    void remove_receiver(ice_receiver &receiver) noexcept {
        auto it = std::ranges::find(_receivers, &receiver);
        if (it != _receivers.end())
            _receivers.erase(it);
    }

  private:
    struct stun_receiver : asioice::datagram_receiver {
        stun_receiver(const asioice::any_transport &transport,
                      agent_base_impl *agent, uint8_t component) noexcept
            : asioice::datagram_receiver(), _transport(transport),
              _agent(agent), _component(component) {
            _transport.add_receiver(*this);
        }
        const auto &transport() const noexcept { return _transport; }
        bool datagram_received(io_buffer_ptr &buffer,
                               const asioice::endpoint &endpoint) override;

      private:
        asioice::any_transport _transport;
        agent_base_impl *_agent;
        uint8_t _component;
    };

    struct check_task {
        std::shared_ptr<asioice::candidate_pair> pair;
        std::shared_ptr<asioice::candidate_pair> triggered_by{nullptr};
        bool use_candidate{false};
        uint64_t priority{0};
    };

    struct valid_pair {
        std::shared_ptr<asioice::candidate_pair> pair;
        std::shared_ptr<asioice::candidate_pair> source;
        bool nominated = false;
        uint32_t generation = 0;
    };

    struct transaction_state
        : boost::intrusive::set_base_hook<
              boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
        transaction_state(asioice::candidate_pair &p,
                          stun::transaction &t) noexcept
            : pair{&p}, transaction{&t} {}

        struct key_type {
            using type = asioice::candidate_pair *;
            type operator()(const transaction_state &s) const noexcept {
                return s.pair;
            }
        };
        asioice::candidate_pair *pair;
        stun::transaction *transaction;
    };

    using transaction_state_set = boost::intrusive::multiset<
        transaction_state,
        boost::intrusive::key_of_value<typename transaction_state::key_type>,
        boost::intrusive::constant_time_size<false>>;

    enum struct request_result : char { succeed, failed, canceled };

    asioice::task<void> do_gather_candidates();

    asioice::task<void> get_component_candidates(
        std::vector<asioice::candidate> &component_candidates,
        uint8_t component, const std::vector<net::ip::address> &addresses);

    asioice::task<void> server_reflexive_candidate(
        std::vector<asioice::candidate> &srflx_candidates,
        const asioice::candidate &local_candidate,
        stun::transaction_set &transactions,
        asioice::endpoint stun_server) noexcept;

    asioice::task<void> server_reflexive_candidate(
        std::vector<asioice::candidate> &srflx_candidates,
        const std::vector<asioice::candidate> &local_candidates,
        const std::vector<resolved_result> &stun_servers) noexcept;

    asioice::task<void> create_relayed_candidate(
        std::vector<asioice::candidate> &component_candidates,
        std::shared_ptr<turn::turn_interface> client,
        any_transport host_transport, uint8_t component) noexcept;

    void pair_local_candidate(const asioice::candidate &c);
    void pair_remote_candidate(const asioice::candidate &c);
    void init_pair_state(asioice::candidate_pair &pair) const noexcept;

    void generate_gathering_end_indication() noexcept;

    void sort_check_list() noexcept;

    check_task pick_next_pair() noexcept;

    void unfreeze_initial() noexcept;

    asioice::task<request_result> request(asioice::candidate_pair &pair,
                                          const stun::message &req,
                                          stun::message &resp) noexcept;

    void switch_role(bool ice_controlling) noexcept;

    void set_check_list_state(check_list_state_t s) noexcept {
        _check_list_state = s;
    }

    std::shared_ptr<asioice::candidate_pair>
    construct_valid_pair(const stun::message &req, const stun::message &resp,
                         check_task &ct);

    void build_request(stun::message &req,
                       asioice::candidate_pair &pair) noexcept;

    bool
    in_triggered_check_queue(const asioice::candidate_pair &p) const noexcept;

    asioice::task<void> check(check_task ct);
    asioice::task<void> do_check(check_task ct);

    bool verify_username(std::string_view name) const noexcept;

    asioice::task<void> do_handle_request(asioice::any_transport transport,
                                          asioice::endpoint source,
                                          asioice::io_buffer_ptr buf);

    asioice::task<bool> do_connect() noexcept;

    template <class Transport>
    auto send_stun(Transport &transport, const stun::message &msg,
                   const asioice::endpoint &ep) {
        auto byte_size = msg.serialized_size();
        return stdexec::just(
                   boost::container::small_vector<std::byte, 1024>(byte_size)) |
               stdexec::let_value([&](auto &buf) {
                   int n = msg.write_to(buf.data(), buf.size());
                   assert(n > 0);
                   buf.resize(n);
                   return transport.async_send_to(
                       net::const_buffer{buf.data(), buf.size()}, ep);
               });
    }

    void check_complete(asioice::candidate_pair &pair) noexcept;

    void request_handler(asioice::any_transport &transport,
                         const asioice::endpoint &source,
                         asioice::io_buffer_ptr buf);

    void create_stun_receiver(const asioice::any_transport &transport,
                              uint8_t component) noexcept;
    void create_turn_permission(const net::ip::address &ip);

    bool set_nominated(asioice::candidate_pair &pair) noexcept;
    void default_nominate();

    asioice::task<void> free_candidates();

    void create_channel_for_valid_pair();

    void dispatch_received_data(asioice::io_buffer_ptr buffer,
                                uint8_t component);

    using check_list_type =
        std::vector<std::shared_ptr<asioice::candidate_pair>>;

    using valid_list_type = std::vector<valid_pair>;

    net::any_io_executor _any_executor;
    agent_base *_agent;
    asioice::shared_promise<void> _promise{}; // use for some detached work
    stun::transaction_set _transactions{};    // use for connectivity checks
    transaction_state_set _transaction_states{};
    agent_config _config;
    std::vector<resolved_result> _stun_servers{};
    std::vector<resolved_result> _turn_servers{};
    std::shared_ptr<io_buffer_pool> _pool;
    bool _remote_is_lite = false;
    std::string _remote_username{};
    std::string _remote_password{};
    uint64_t _tie_breaker = 0;
    uint32_t _generation = 0;
    boost::container::flat_map<net::ip::address, std::string> _mdns_names{};
    std::vector<asioice::candidate> _local_candidates{};
    std::vector<asioice::candidate> _remote_candidates{};
    bool _local_candidates_end = false;
    bool _remote_candidates_end = false;
    check_list_type _check_list{};
    asioice::utils::property<check_list_state_t> _check_list_state{
        check_list_state_t::RUNNING};
    valid_list_type _valid_list{};
    std::deque<check_task> _triggered_check_queue{};
    std::size_t _pending_check_count{0};
    asioice::shared_promise<void> _check_complete_notifier{};
    asioice::shared_promise<void> _request_handler_promise{};
    std::size_t _outgoing_request_handler_count{0};
    std::vector<ice_receiver *> _receivers{};
    boost::compat::move_only_function<void(asioice::io_buffer_ptr &, uint8_t)>
        _on_data{};
    std::list<stun_receiver> _stun_receivers{};
    asioice::utils::property<agent_state_t> _state{agent_state_t::INIT};

    // callbacks
    boost::compat::move_only_function<void(std::span<const asioice::candidate>)>
        _on_local_candidates{};
};

} // namespace asioice