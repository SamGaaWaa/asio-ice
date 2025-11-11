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
#include "small_set.hpp"
#include "stun_transaction.hpp"

#include <exec/async_scope.hpp>

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
#include <memory>
#include <algorithm>
#include <ranges>

namespace ice::impl {

template <class Layer>
struct agent_datagram_impl
    : std::enable_shared_from_this<agent_datagram_impl<Layer>> {
    using socket_type = Layer;
    using raw_transport = datagram_transport<Layer>;
    using raw_transport_ptr = std::shared_ptr<raw_transport>;
    using config_type = agent_config;

    agent_datagram_impl(net::io_context &ctx, config_type config) noexcept
        : _ctx(ctx), _config(std::move(config)),
          _ice_controlling(_config.ice_controlling) {}

    agent_datagram_impl(const agent_datagram_impl &) = delete;
    agent_datagram_impl &operator=(const agent_datagram_impl &) = delete;
    agent_datagram_impl(agent_datagram_impl &&) = delete;
    agent_datagram_impl &operator=(agent_datagram_impl &&) = delete;

    const auto &local_candidates() const noexcept { return _local_candidates; }
    const auto &context() const noexcept { return _ctx; }
    auto &context() noexcept { return _ctx; }
    const auto &config() const noexcept { return _config; }

    const auto &candidate_pairs() const noexcept { return _check_list; }

    const auto &local_username() const noexcept { return _local_username; }
    const auto &remote_username() const noexcept { return _remote_username; }
    const auto &local_password() const noexcept { return _local_password; }
    const auto &remote_password() const noexcept { return _remote_password; }

    void clear() noexcept;

    void build_request(stun::message &req, ice::candidate_pair &pair,
                       bool nominate) noexcept;

    ice::task<bool> request(ice::candidate_pair &pair, const stun::message &req,
                            stun::message &resp) noexcept;

    ice::task<void> check(ice::candidate_pair &pair) noexcept;

    void switch_role(bool ice_controlling) noexcept;

    ice::task<void> gather_candidates(auto... self);

    ice::task<bool> add_remote_candidate(ice::candidate c, auto... self);

    ice::task<void> get_component_candidates(
        std::vector<ice::candidate> &component_candidates, uint8_t component,
        const std::vector<net::ip::address> &addresses, auto... self);

    ice::task<void>
    server_reflexive_candidate(std::vector<ice::candidate> &srflx_candidates,
                               const ice::candidate &local_candidate,
                               stun::transaction_set &transactions,
                               const ice::endpoint &stun_server,
                               auto... self) noexcept;

    ice::task<void> server_reflexive_candidate(
        std::vector<ice::candidate> &srflx_candidates,
        const std::vector<ice::candidate> &local_candidates,
        const std::vector<ice::endpoint> &stun_servers, auto... self) noexcept;

    void sort_check_list() noexcept;

    ice::candidate_pair *
    find_pair(const ice::any_transport &transport,
              const ice::candidate &remote_candidate) const noexcept;

    ice::candidate_pair *pick_next_pair() noexcept;

    void unfreeze_initial() noexcept;

    ice::task<bool> connect(auto... self) noexcept;

    void check_complete(const ice::candidate_pair &pair) noexcept;

  private:
    using triggered_check_queue_type = boost::intrusive::list<
        candidate_pair,
        boost::intrusive::base_hook<__triggered_check_queue_base_hook>,
        boost::intrusive::constant_time_size<false>>;

    using check_list_type = std::vector<std::shared_ptr<ice::candidate_pair>>;

    using valid_list_type = std::vector<std::shared_ptr<ice::candidate_pair>>;

    net::io_context &_ctx;
    stun::transaction_set _transactions{}; // use for connectivity checks
    config_type _config;
    bool _ice_controlling = true;
    bool _remote_is_lite = false;
    std::string _local_username;
    std::string _remote_username;
    std::string _local_password;
    std::string _remote_password;
    uint64_t _tie_breaker = 0;
    std::vector<ice::candidate> _local_candidates{};
    std::vector<ice::candidate> _remote_candidates{};
    check_list_type _check_list{};
    valid_list_type _valid_list{};
    triggered_check_queue_type _triggered_check_queue{};
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

    const char *stun_servers[] = {"stun.l.google.com:19302",
                                  "14.29.112.241:20002"};

    agent_config config;
    config.component_count = 2; // 1 for RTP, 1 for RTCP
    {
        net::ip::udp::resolver resolver(ctx);
        net::steady_timer timer(ctx, std::chrono::seconds(3));
        exec::async_scope scope;
        for (const auto &stun_server : stun_servers) {
            scope.spawn(
                resolve_server(resolver, stun_server, config.stun_servers));
        }
        co_await utils::stop_when(utils::on_scope_empty(scope),
                                  timer.async_wait(asio2exec::use_sender));
    }
    if (config.stun_servers.empty()) {
        std::cerr << "Failed to resolve STUN server\n";
        co_return;
    }

    auto agent1 =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx, config);

    config.ice_controlling = false;
    auto agent2 =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx, config);

    utils::scope_guard on_exit([&]() noexcept {
        agent1->clear();
        agent2->clear();
    });

    net::steady_timer timer(ctx, std::chrono::seconds(5));
    std::cout << "Gathering ...\n";
    co_await utils::stop_when(stdexec::when_all(agent1->gather_candidates(),
                                                agent2->gather_candidates()),
                              timer.async_wait(asio2exec::use_sender));
    std::cout << "Gathering done.\n\n";

    std::cout << "Agent1 local candidates:\n";
    for (const auto &c : agent1->local_candidates())
        std::cout << c.to_string() << '\n';
    std::cout << "\nAgent2 local candidates:\n";
    for (const auto &c : agent2->local_candidates())
        std::cout << c.to_string() << '\n';
    std::cout << '\n';

    std::cout << "Adding remote candidates ...\n";
    for (const auto &c : agent2->local_candidates()) {
        co_await agent1->add_remote_candidate(c);
    }
    for (const auto &c : agent1->local_candidates()) {
        co_await agent2->add_remote_candidate(c);
    }
    std::cout << "Adding remote candidates done.\n\n";

    std::cout << "Agent1 candidate pairs:\n";
    for (const auto &p : agent1->candidate_pairs()) {
        // std::cout << "type " << ice::to_string(p->local_candidate().type) <<
        // " component: " << (int)p->local_candidate().component << '\n';

        if (p->local_candidate().type == candidate_type::srflx) {
            std::cerr
                << "Candidate pair's local candidate is a srflx candidate, but it should not be used.\n";
            std::abort();
        }
        std::cout << "Type: " << ice::to_string(p->local_candidate().type)
                  << " From " << p->local_candidate().endpoint.to_string()
                  << " to " << p->remote_candidate().endpoint.to_string()
                  << '\n';
    }
    std::cout << "\nAgent2 candidate pairs:\n";
    for (const auto &p : agent2->candidate_pairs()) {
        if (p->local_candidate().type == candidate_type::srflx) {
            std::cerr
                << "Candidate pair's local candidate is a srflx candidate, but it should not be used.\n";
            std::abort();
        }
        std::cout << "Type: " << ice::to_string(p->local_candidate().type)
                  << " From " << p->local_candidate().endpoint.to_string()
                  << " to " << p->remote_candidate().endpoint.to_string()
                  << '\n';
    }

    std::cout << "\nConnecting...\n";
    bool connected = co_await agent1->connect();
} catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << '\n';
    co_return;
}

void gathering_test(int num) {
    ice::net::io_context ctx;
    stdexec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, gather_task(ctx)));
    ctx.run();
}

namespace ice {
void debug_test() {
    // get_local_addresses_test(1000);
    gathering_test(1);
}
} // namespace ice