#include "ice_impl.hpp"

#include <iostream>

inline asioice::task<void>
resolve_server(asioice::net::ip::udp::resolver &resolver,
               std::string_view stun_server,
               std::vector<asioice::endpoint> &endpoints) {
    using namespace asioice;
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
    using namespace asioice;
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

inline asioice::task<void> gather_task(asioice::net::io_context &ctx,
                                       int num) try {
    using namespace asioice;

    const char *stun_servers[] = {/*"stun.l.google.com:19302",*/
                                  "14.29.112.241:20002"};

    agent_config config1 = {
        .username = "user1",
        .password = "pass1",
        .ice_controlling = true,
        .turn_servers = {{{net::ip::make_address("127.0.0.1"), 13478},
                          "samgaawaa",
                          "1234"}},
        .component_count = 2,
        .transport_policy = asioice::transport_policy::ALL};

    auto agent1 =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx.get_executor(), config1);

    agent_config config2 = {
        .username = "user2",
        .password = "pass2",
        .ice_controlling = false,
        .stun_servers =
            {
                {net::ip::make_address("14.29.112.241"), 20002},
            },
        .component_count = 2,
        .transport_policy = asioice::transport_policy::ALL};
    auto agent2 =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx.get_executor(), config2);

    utils::scope_guard on_exit([&]() noexcept {
        agent1->close();
        agent2->close();
    });

    // Trickle ICE
    exec::async_scope scope;
    asio2exec::scheduler sched{ctx};
    net::steady_timer network_timer(ctx.get_executor());
    auto network_latency = std::chrono::milliseconds(60);

    net::steady_timer timer1(ctx.get_executor(), std::chrono::seconds(5));
    net::steady_timer timer2(ctx.get_executor(), std::chrono::seconds(5));

    agent2->on_data([&](io_buffer_ptr data, uint8_t component) {
        // remove header
        data->consume_front(1);
        if (component == 1)
            std::cout << "RTP from agent1: "
                      << std::string_view{(const char *)data->data(),
                                          data->size()}
                      << '\n';
        else if (component == 2)
            std::cout << "RTCP from agent1: "
                      << std::string_view{(const char *)data->data(),
                                          data->size()}
                      << '\n';
    });

    agent1->on_local_candidates(
        [&agent2](const asioice::candidate *c,
                  std::size_t n) -> asioice::task<void> {
            if (!c) {
                std::cout << "Agent1 finish gathering\n";
                co_await agent2->add_remote_candidate();
                co_return;
            }
            net::steady_timer timer(agent2->get_executor(),
                                    std::chrono::milliseconds(60));
            for (std::size_t i = 0; i < n; ++i) {
                std::cout << "Agent1's local candidates: " << c[i].to_string()
                          << '\n';
            }
            std::cout << "Agent1 is sending local candidates to agent2\n";
            // Simulate network latency
            co_await timer.async_wait(asio2exec::use_sender);
            for (std::size_t i = 0; i < n; ++i) {
                co_await agent2->add_remote_candidate(c[i]);
            }
        });

    agent2->on_local_candidates(
        [&agent1](const asioice::candidate *c,
                  std::size_t n) -> asioice::task<void> {
            if (!c) {
                std::cout << "Agent2 finish gathering\n";
                co_await agent1->add_remote_candidate();
                co_return;
            }
            net::steady_timer timer(agent1->get_executor(),
                                    std::chrono::milliseconds(60));
            for (std::size_t i = 0; i < n; ++i) {
                std::cout << "Agent2's local candidates: " << c[i].to_string()
                          << '\n';
            }
            std::cout << "Agent2 is sending local candidates to agent1\n";
            // Simulate network latency
            co_await timer.async_wait(asio2exec::use_sender);
            for (std::size_t i = 0; i < n; ++i) {
                co_await agent1->add_remote_candidate(c[i]);
            }
        });

    std::cout << "Agent1 is gathering...\n";
    scope.spawn(
        stdexec::starts_on(
            sched, utils::stop_when(agent1->gather_candidates(),
                                    timer1.async_wait(asio2exec::use_sender))) |
        utils::ignore());

    std::cout << "Agent1 create OFFER with empty candidate list\n";
    std::cout << "Agent1 will response early checks\n";
    // Simulate network latency
    network_timer.expires_after(network_latency);
    co_await network_timer.async_wait(asio2exec::use_sender);

    agent2->set_remote_username(agent1->local_username());
    agent2->set_remote_password(agent1->local_password());

    std::cout << "Agent2 is gathering...\n";
    scope.spawn(
        stdexec::starts_on(
            sched, utils::stop_when(agent2->gather_candidates(),
                                    timer2.async_wait(asio2exec::use_sender))) |
        utils::ignore());
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

    co_await (asioice::utils::on_scope_empty(scope) |
              stdexec::continues_on(sched));

    bool agent1_connected = agent1->state() == impl::agent_state_t::CONNECTED;
    bool agent2_connected = agent2->state() == impl::agent_state_t::CONNECTED;
    if (agent1_connected && agent2_connected) {
        std::cout << "Connect success\n";
        auto np1 = agent1->nominated_pairs();
        auto np2 = agent2->nominated_pairs();
        std::cout << "\nAgent1's nominated pairs:\n";
        for (const auto &p : np1) {
            std::cout << p->to_string() << '\n';
        }
        std::cout << "\nAgent2's nominated pairs:\n";
        for (const auto &p : np2) {
            std::cout << p->to_string() << '\n';
        }
        std::string_view rtp =
            /*demultiplex with STUN*/ "\12This is RTP packet";
        std::string_view rtcp =
            /*demultiplex with STUN*/ "\12This is RTCP packet";
        for (int i = 0; i < num; ++i) {
            if (rand() % 2)
                co_await agent1->sendto(net::buffer(rtp), 1);
            else
                co_await agent1->sendto(net::buffer(rtcp), 2);
            timer1.expires_after(std::chrono::seconds(30));
            co_await timer1.async_wait(asio2exec::use_sender);
        }
    } else {
        std::cout << "Agent1 connect "
                  << (agent1_connected ? "success, " : "failed, ")
                  << "agent2 connect "
                  << (agent2_connected ? "success\n" : "failed\n");
    }
} catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << '\n';
    co_return;
}

void gathering_test(int num) {
    asioice::net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, gather_task(ctx, num)));
    ctx.run();
}

int main(int argc, char *argv[]) {
    gathering_test(argc > 1 ? std::atoi(argv[1]) : 100);
}