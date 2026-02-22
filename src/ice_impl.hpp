#pragma once

#include "agent_config.hpp"
#include "ice.hpp"
#include "address.hpp"
#include "candidate_pair.hpp"
#include "config.hpp"
#include "scope_guard.hpp"
#include "stun.hpp"
#include "task.hpp"
#include "socket_transport.hpp"
#include "stop_when.hpp"
#include "scope_guard.hpp"
#include "on_scope_empty.hpp"
#include "if_else.hpp"
#include "small_set.hpp"
#include "stun_transaction.hpp"
#include "string_utils.hpp"
#include "hash.hpp"
#include "property.hpp"
#include "async_function.hpp"
#include "ignore.hpp"
#include "turn_client.hpp"
#include "detached_with_data.hpp"

#include <exec/async_scope.hpp>
#include <exec/finally.hpp>
#include <exec/start_detached.hpp>
#include <exec/repeat_until.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include "asio2exec.hpp"
#include <asio/io_context.hpp>
#include <asio/ip/host_name.hpp>
#include <asio/ip/basic_endpoint.hpp>
#include <asio/ip/udp.hpp>
#include <asio/as_tuple.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <chrono>
#include <iostream>
#include <optional>
#include <vector>
#include <deque>
#include <list>
#include <memory>
#include <algorithm>
#include <ranges>

#include <boost/intrusive/set.hpp>
#include <boost/container/flat_map.hpp>

namespace ice::impl {

enum struct agent_state_t: char {
    INIT,
    GATHERING,
    CONNECTING,
    CONNECTED,
    CLOSED
};

enum struct check_list_state_t {
    RUNNING,
    COMPLETED,
    FAILED
};

template <class Layer>
struct agent_datagram_impl
    : std::enable_shared_from_this<agent_datagram_impl<Layer>> {
    using socket_type = Layer;
    using raw_transport = datagram_transport<Layer>;
    using raw_transport_ptr = std::shared_ptr<raw_transport>;
    using config_type = agent_config;
    using turn_client_type = ice::turn::client<raw_transport, true>;

    agent_datagram_impl(net::io_context &ctx, config_type config) noexcept
        : _ctx(ctx), _config(std::move(config)),
          _ice_controlling(_config.ice_controlling)
    {
        ice::hash::random_bytes(&_tie_breaker, sizeof(_tie_breaker));
    }

    agent_datagram_impl(const agent_datagram_impl &) = delete;
    agent_datagram_impl &operator=(const agent_datagram_impl &) = delete;
    agent_datagram_impl(agent_datagram_impl &&) = delete;
    agent_datagram_impl &operator=(agent_datagram_impl &&) = delete;

    const auto &local_candidates() const noexcept { return _local_candidates; }
    const auto &remote_candidates() const noexcept { return _remote_candidates; }
    const auto &context() const noexcept { return _ctx; }
    auto &context() noexcept { return _ctx; }
    const auto &config() const noexcept { return _config; }

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

    agent_state_t state() const noexcept { return _state; }
    auto on_state_change() noexcept {
        return _state.on_change() |
            stdexec::continues_on(asio2exec::scheduler{_ctx});
    }
    auto on_closed() noexcept;
    auto on_connected_or_closed() noexcept;

    check_list_state_t check_list_state() const noexcept {
        return _check_list_state;
    }

    void close() noexcept;

    bool all_components_nominated() const noexcept;
    bool all_components_have_valid_pair() const noexcept;

    auto gather_candidates() {
        return utils::stop_when(
            this->do_gather_candidates(),
            this->on_connected_or_closed()
        );
    }

    ice::task<bool> add_remote_candidate(ice::candidate c, auto... self);
    auto add_remote_candidate() noexcept {
        this->_remote_candidates_end = true;
        return stdexec::just(true);
    }

    auto connect(auto... self) noexcept {
        return utils::stop_when(
            this->do_connect(std::move(self)...),
            this->on_closed()
        );
    }

    boost::container::small_vector<ice::candidate_pair*, 2>
    nominated_pairs() const;

    template <class Func>
    void on_local_candidates(Func&& cb) {
        _on_local_candidates = std::forward<Func>(cb);
    }
  private:
    struct stun_receiver: ice::datagram_receiver {
        stun_receiver(const ice::any_transport& transport, agent_datagram_impl *agent) noexcept
            : ice::datagram_receiver(),
            _transport(transport),
            _agent(agent) {
            _transport.add_receiver(*this);
        }
        const auto& transport() const noexcept {
            return _transport;
        }
        bool datagram_received(io_buffer_ptr &buffer, const ice::endpoint &endpoint) override;
    private:
        ice::any_transport _transport;
        agent_datagram_impl *_agent;
    };

    struct check_task {
        std::shared_ptr<ice::candidate_pair> pair;
        std::shared_ptr<ice::candidate_pair> triggered_by{nullptr};
        bool use_candidate{false};
        uint64_t priority{0};
    };

    struct valid_pair {
        std::shared_ptr<ice::candidate_pair> pair;
        std::shared_ptr<ice::candidate_pair> source;
        bool nominated = false;
    };

    struct transaction_state:
        boost::intrusive::set_base_hook<boost::intrusive::link_mode<boost::intrusive::auto_unlink>>
    {
        transaction_state(ice::candidate_pair& p, stun::transaction& t) noexcept:
            pair{&p},
            transaction{&t}
        {}

        struct key_type {
            using type = ice::candidate_pair*;
            type operator()(const transaction_state &s) const noexcept {
                return s.pair;
            }
        };
        ice::candidate_pair *pair;
        stun::transaction *transaction;
    };

    using transaction_state_set = boost::intrusive::multiset<
            transaction_state,
            boost::intrusive::key_of_value<typename transaction_state::key_type>,
            boost::intrusive::constant_time_size<false>>;

    enum struct request_result: char {
        succeed, failed, canceled
    };

    ice::task<void> do_gather_candidates();

    ice::task<void> get_component_candidates(
        std::vector<ice::candidate> &component_candidates, uint8_t component,
        const std::vector<net::ip::address> &addresses, auto... self);

    ice::task<void>
    server_reflexive_candidate(std::vector<ice::candidate> &srflx_candidates,
                               const ice::candidate &local_candidate,
                               stun::transaction_set &transactions,
                               const ice::endpoint &stun_server) noexcept;

    ice::task<void> server_reflexive_candidate(
        std::vector<ice::candidate> &srflx_candidates,
        const std::vector<ice::candidate> &local_candidates,
        const std::vector<ice::endpoint>& stun_servers) noexcept;

    ice::task<void>
    create_relayed_candidate(std::vector<ice::candidate> &component_candidates,
                                std::shared_ptr<turn_client_type> client,
                                raw_transport_ptr host_transport,
                               uint8_t component) noexcept;

    void pair_local_candidate(const ice::candidate& c);
    void pair_remote_candidate(const ice::candidate& c);
    void init_pair_state(ice::candidate_pair& pair) const noexcept;
    auto generate_gathering_end_indication() noexcept;
    void sort_check_list() noexcept;

    ice::candidate_pair *
    find_pair(const ice::any_transport &transport,
              const ice::candidate &remote_candidate) const noexcept;

    check_task pick_next_pair() noexcept;

    void unfreeze_initial() noexcept;

    ice::task<request_result> request(ice::candidate_pair &pair, const stun::message &req,
                            stun::message &resp) noexcept;

    void switch_role(bool ice_controlling) noexcept;

    void set_check_list_state(check_list_state_t s) noexcept {
        _check_list_state = s;
    }

    std::shared_ptr<ice::candidate_pair> construct_valid_pair(
        const stun::message& req,
        const stun::message& resp,
        check_task& ct
    );

    void build_request(stun::message &req, ice::candidate_pair &pair) noexcept;

    bool in_triggered_check_queue(const ice::candidate_pair& p) const noexcept;

    ice::task<void> check(check_task ct);
    ice::task<void> do_check(check_task ct);

    bool verify_username(std::string_view name) const noexcept;

    ice::task<void> do_handle_request(
        ice::any_transport transport,
        ice::endpoint source,
        ice::io_buffer_ptr buf);

    ice::task<bool> do_connect(auto... self) noexcept;

    template <class Transport>
    auto send_stun(Transport& transport, const stun::message& msg, const ice::endpoint& ep);

    void check_complete(ice::candidate_pair &pair) noexcept;

    void request_handler(ice::any_transport& transport, const ice::endpoint &source, ice::io_buffer_ptr buf);

    void create_stun_receiver(const ice::any_transport& transport) noexcept;
    void create_turn_permission(const net::ip::address& ip);

    bool set_nominated(ice::candidate_pair& pair) noexcept;
    void default_nominate();

    ice::task<void> free_candidates();

    using check_list_type = std::vector<std::shared_ptr<ice::candidate_pair>>;

    using valid_list_type = std::vector<valid_pair>;

    net::io_context &_ctx;
    ice::shared_promise<void> _promise{}; // use for some detached work
    stun::transaction_set _transactions{}; // use for connectivity checks
    transaction_state_set _transaction_states{};
    config_type _config;
    bool _ice_controlling = true;
    bool _remote_is_lite = false;
    std::string _remote_username;
    std::string _remote_password;
    uint64_t _tie_breaker = 0;
    std::vector<ice::candidate> _local_candidates{};
    std::vector<ice::candidate> _remote_candidates{};
    bool _local_candidates_end = false;
    bool _remote_candidates_end = false;
    // std::vector<turn_client_type> _turn_clients;
    check_list_type _check_list{};
    ice::utils::property<check_list_state_t> _check_list_state{check_list_state_t::RUNNING};
    valid_list_type _valid_list{};
    std::deque<check_task> _triggered_check_queue{};
    std::size_t _pending_check_count{0};
    ice::shared_promise<void> _check_complete_notifier{};
    ice::shared_promise<void> _request_handler_promise{};
    std::size_t _outgoing_request_handler_count{0};
    std::list<stun_receiver> _stun_receivers{};
    ice::utils::property<agent_state_t> _state{agent_state_t::INIT};

    // callbacks
    utils::async_function<void(const ice::candidate*, std::size_t)> _on_local_candidates{};
};

} // namespace ice::impl

#include "impl/ice_impl.ipp"

inline ice::task<void> resolve_server(ice::net::ip::udp::resolver &resolver,
                                      std::string_view stun_server,
                                      std::vector<ice::endpoint> &endpoints) {
    using namespace ice;
    if (stun_server.size() < 1)
        co_return;
    std::string_view host, port;
    {
        auto idx = stun_server.find_last_of(':');
        if (idx == std::string_view::npos) {
            host = stun_server;
            port = "";
        } else {
            host = std::string_view{stun_server.data(), idx};
            port = std::string_view{stun_server.begin() + idx + 1,
                                    stun_server.end()};
        }
    }

    auto opt = co_await (resolver.async_resolve(
                             host, port, net::as_tuple(asio2exec::use_sender)) |
                         stdexec::stopped_as_optional());
    if (!opt) {
        ICE_IN_DEBUG {
            std::cerr << "resolve_server timeout: " << stun_server << '\n';
        }
        co_return;
    }
    const auto &[ec, result] = *opt;
    if (ec) {
        ICE_IN_DEBUG {
            std::cerr << "resolve_server error " << stun_server << ": "
                      << ec.message() << '\n';
        }
        co_return;
    }
    if (result.empty()) {
        ICE_IN_DEBUG {
            std::cerr << "resolve_server no result: " << stun_server << '\n';
        }
        co_return;
    }

    for (auto it = result.begin(); it != result.end(); ++it) {
        endpoints.emplace_back(it->endpoint());
    }
}

inline void get_local_addresses_test(uint64_t n) {
    using namespace ice;
    int addrs_num = 0;
    auto begin = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < n; ++i) {
        addrs_num += get_local_addresses().size();
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Result: " << (addrs_num / n) << '\n'
              << "Takes: "
              << (std::chrono::duration_cast<std::chrono::nanoseconds>(end -
                                                                       begin)
                      .count() /
                  n)
              << "ns\n";
}

inline ice::task<void> gather_task(ice::net::io_context &ctx) try {
    using namespace ice;

    const char *stun_servers[] = {/*"stun.l.google.com:19302",*/
                                  "14.29.112.241:20002"};

    agent_config config1 = {
        .username = "user1",
        .password = "pass1",
        .ice_controlling = true,
        .turn_servers = {
            {
                {net::ip::make_address("127.0.0.1"), 13478},
                "samgaawaa",
                "1234"
            }
        },
        .component_count = 2,
        .transport_policy = ice::transport_policy::ALL
    };

    auto agent1 =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx, config1);

    agent_config config2 = {
        .username = "user2",
        .password = "pass2",
        .ice_controlling = false,
        .stun_servers = {
            {net::ip::make_address("14.29.112.241"), 20002},
        },
        .component_count = 2,
        .transport_policy = ice::transport_policy::ALL
    };
    auto agent2 =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx, config2);

    utils::scope_guard on_exit([&]() noexcept {
        agent1->close();
        agent2->close();
    });

    // Trickle ICE
    exec::async_scope scope;
    asio2exec::scheduler sched{ctx};
    net::steady_timer network_timer(ctx);
    auto network_latency = std::chrono::milliseconds(60);

    net::steady_timer timer1(ctx, std::chrono::seconds(5));
    net::steady_timer timer2(ctx, std::chrono::seconds(5));

    agent1->on_local_candidates([&agent2](const ice::candidate *c, std::size_t n)->ice::task<void> {
        if (!c) {
            std::cout << "Agent1 finish gathering\n";
            co_await agent2->add_remote_candidate();
            co_return;
        }
        net::steady_timer timer(agent2->context(), std::chrono::milliseconds(60));
        for (std::size_t i = 0; i < n; ++i) {
            std::cout << "Agent1's local candidates: " << c[i].to_string() << '\n';
        }
        std::cout << "Agent1 is sending local candidates to agent2\n";
        // Simulate network latency
        co_await timer.async_wait(asio2exec::use_sender);
        for (std::size_t i = 0; i < n; ++i) {
            co_await agent2->add_remote_candidate(c[i]);
        }
    });

    agent2->on_local_candidates([&agent1](const ice::candidate *c, std::size_t n)->ice::task<void> {
        if (!c) {
            std::cout << "Agent2 finish gathering\n";
            co_await agent1->add_remote_candidate();
            co_return;
        }
        net::steady_timer timer(agent1->context(), std::chrono::milliseconds(60));
        for (std::size_t i = 0; i < n; ++i) {
            std::cout << "Agent2's local candidates: " << c[i].to_string() << '\n';
        }
        std::cout << "Agent2 is sending local candidates to agent1\n";
        // Simulate network latency
        co_await timer.async_wait(asio2exec::use_sender);
        for (std::size_t i = 0; i < n; ++i) {
            co_await agent1->add_remote_candidate(c[i]);
        }
    });

    std::cout << "Agent1 is gathering...\n";
    scope.spawn(stdexec::starts_on(sched, utils::stop_when(
                                agent1->gather_candidates(),
                              timer1.async_wait(asio2exec::use_sender))) | utils::ignore());

    std::cout << "Agent1 create OFFER with empty candidate list\n";
    std::cout << "Agent1 will response early checks\n";
    // Simulate network latency
    network_timer.expires_after(network_latency);
    co_await network_timer.async_wait(asio2exec::use_sender);

    agent2->set_remote_username(agent1->local_username());
    agent2->set_remote_password(agent1->local_password());

    std::cout << "Agent2 is gathering...\n";
    scope.spawn(stdexec::starts_on(sched, utils::stop_when(
                                agent2->gather_candidates(),
                              timer2.async_wait(asio2exec::use_sender))) | utils::ignore());
    std::cout << "Agent2 is connecting ...\n";
    scope.spawn(stdexec::starts_on(sched, agent2->connect()) | utils::ignore());

    std::cout << "Agent2 create ANSWER with empty candidate list\n";
    // Simulate network latency
    network_timer.expires_after(network_latency);
    co_await network_timer.async_wait(asio2exec::use_sender);
    agent1->set_remote_username(agent2->local_username());
    agent1->set_remote_password(agent2->local_password());

    std::cout << "Agent1 is connecting ...\n";
    scope.spawn(stdexec::starts_on(sched, agent1->connect()) | utils::ignore());

    co_await ice::utils::on_scope_empty(scope);

    bool agent1_connected = agent1->state() == impl::agent_state_t::CONNECTED;
    bool agent2_connected = agent2->state() == impl::agent_state_t::CONNECTED;
    if (agent1_connected && agent2_connected) {
        std::cout << "Connect success\n";
        auto np1 = agent1->nominated_pairs();
        auto np2 = agent2->nominated_pairs();
        std::cout << "\nAgent1's nominated pairs:\n";
        for (const auto& p: np1) {
            std::cout << p->to_string() << '\n';
        }
        std::cout << "\nAgent2's nominated pairs:\n";
        for (const auto& p: np2) {
            std::cout << p->to_string() << '\n';
        }
    } else {
        std::cout << "Agent1 connect " << (agent1_connected ? "success, " : "failed, ")
                << "agent2 connect " << (agent2_connected ? "success\n" : "failed\n");
    }
} catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << '\n';
    co_return;
}

void gathering_test(int num) {
    ice::net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, gather_task(ctx)));
    ctx.run();
}

namespace ice {
void debug_test() {
    // get_local_addresses_test(1000);
    gathering_test(1);
}
} // namespace ice