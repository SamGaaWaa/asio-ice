#include "asioice/agent.hpp"
#include "asioice/detail/ignore.hpp"
#include "asioice/detail/on_scope_empty.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/dtls_transport.hpp"
#include "asioice/sctp_transport.hpp"
#include "asioice/socket_transport.hpp"
#include "asioice/detail/asio2exec.hpp"
#include "asioice/data_channel.hpp"

#include <exec/start_detached.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/host_name.hpp>
#include <asio/ip/basic_endpoint.hpp>
#include <asio/ip/udp.hpp>
#include <asio/as_tuple.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <iostream>
#include <thread>

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

asioice::task<std::string> async_cin(auto ex) {
    std::string res;
    asioice::shared_promise<void> p;
    std::thread([&] {
        std::cin >> res;
        asioice::net::post(ex, [&] { p.set_value(); });
    }).detach();
    co_await p.get_future();
    co_return res;
}

inline asioice::task<void> gather_task(asioice::net::io_context &ctx,
                                       int num) try {
    using namespace asioice;
    using Agent = asioice::agent;
    using IceTransport = typename Agent::ice_transport_type;
    using DtlsTransport = ssl::dtls_transport<IceTransport>;
    using SctpTransport = sctp::transport<DtlsTransport>;
    using DataChannelManager = data_channel_manager<SctpTransport>;
    using DataChannel = typename DataChannelManager::data_channel;

    const char *stun_servers[] = {/*"stun.l.google.com:19302",*/
                                  "14.29.112.241:20002"};

    ssl::dtls_certificate server_cert, client_cert;
    std::string server_fp = server_cert.get_fingerprint_sha256();
    std::string client_fp = client_cert.get_fingerprint_sha256();

    agent_config config1 = {
        .username = "user1",
        .password = "pass1",
        .ice_controlling = true,
        .turn_servers = {{{net::ip::make_address("127.0.0.1"), 13478},
                          "samgaawaa",
                          "1234"}},
        .component_count = 1,
        .transport_policy = asioice::transport_policy::ALL,
        .enable_mdns = true};
    Agent agent1(ctx.get_executor(), config1);
    std::shared_ptr<IceTransport> transport1 = agent1.create_ice_transport(1);
    auto dtls_client =
        std::make_shared<DtlsTransport>(transport1, std::move(client_cert));
    auto sctp_client = std::make_shared<SctpTransport>(dtls_client);

    dtls_client->set_expected_remote_fingerprint(server_fp);

    agent_config config2 = {
        .username = "user2",
        .password = "pass2",
        .ice_controlling = false,
        .stun_servers =
            {
                {net::ip::make_address("14.29.112.241"), 20002},
            },
        .component_count = 1,
        .transport_policy = asioice::transport_policy::ALL};
    Agent agent2(ctx.get_executor(), config2);
    std::shared_ptr<IceTransport> transport2 = agent2.create_ice_transport(1);
    auto dtls_server =
        std::make_shared<DtlsTransport>(transport2, std::move(server_cert));
    auto sctp_server = std::make_shared<SctpTransport>(dtls_server);

    dtls_server->set_expected_remote_fingerprint(client_fp);

    // Trickle ICE
    exec::async_scope scope;
    utils::scheduler sched{ctx};
    net::steady_timer network_timer(ctx.get_executor());
    auto network_latency = std::chrono::milliseconds(60);

    net::steady_timer timer1(ctx.get_executor(), std::chrono::seconds(5));
    net::steady_timer timer2(ctx.get_executor(), std::chrono::seconds(5));

    agent1.on_local_candidates([&](std::span<const asioice::candidate> c) {
        if (c.empty()) {
            std::cout << "Agent1 finish gathering\n";
            scope.spawn(agent2.add_remote_candidate() | utils::ignore());
            return;
        }
        for (std::size_t i = 0; i < c.size(); ++i) {
            std::cout << "Agent1's local candidates: " << c[i].to_string()
                      << '\n';
        }
        std::cout << "Agent1 is sending local candidates to agent2\n";

        std::vector<asioice::candidate> candidates(c.begin(), c.end());
        // Simulate network latency
        scope.spawn([](auto candidates, auto &agent1,
                       auto &agent2) -> asioice::task<void> {
            net::steady_timer timer(agent1.get_executor(),
                                    std::chrono::milliseconds(60));
            co_await timer.async_wait(utils::use_sender);
            for (auto &c : candidates) {
                co_await agent2.add_remote_candidate(std::move(c));
            }
        }(std::move(candidates), agent1, agent2));
    });

    agent2.on_local_candidates([&](std::span<const asioice::candidate> c) {
        if (c.empty()) {
            std::cout << "Agent2 finish gathering\n";
            scope.spawn(agent1.add_remote_candidate() | utils::ignore());
            return;
        }
        for (std::size_t i = 0; i < c.size(); ++i) {
            std::cout << "Agent2's local candidates: " << c[i].to_string()
                      << '\n';
        }
        std::cout << "Agent2 is sending local candidates to agent1\n";

        std::vector<asioice::candidate> candidates(c.begin(), c.end());
        // Simulate network latency
        scope.spawn([](auto candidates, auto &agent1,
                       auto &agent2) -> asioice::task<void> {
            net::steady_timer timer(agent2.get_executor(),
                                    std::chrono::milliseconds(60));
            co_await timer.async_wait(utils::use_sender);
            for (auto &c : candidates) {
                co_await agent1.add_remote_candidate(std::move(c));
            }
        }(std::move(candidates), agent1, agent2));
    });

    std::cout << "Agent1 is gathering...\n";
    scope.spawn(
        stdexec::starts_on(
            sched, utils::stop_when(agent1.gather_candidates(),
                                    timer1.async_wait(utils::use_sender))) |
        utils::ignore());

    std::cout << "Agent1 create OFFER with empty candidate list\n";
    std::cout << "Agent1 will response early checks\n";
    // Simulate network latency
    network_timer.expires_after(network_latency);
    co_await network_timer.async_wait(utils::use_sender);

    agent2.set_remote_username(agent1.local_username());
    agent2.set_remote_password(agent1.local_password());

    std::cout << "Agent2 is gathering...\n";
    scope.spawn(
        stdexec::starts_on(
            sched, utils::stop_when(agent2.gather_candidates(),
                                    timer2.async_wait(utils::use_sender))) |
        utils::ignore());
    std::cout << "Agent2 is connecting ...\n";
    scope.spawn(stdexec::starts_on(sched, agent2.connect()) | utils::ignore());

    std::cout << "Agent2 create ANSWER with empty candidate list\n";
    // Simulate network latency
    network_timer.expires_after(network_latency);
    co_await network_timer.async_wait(utils::use_sender);
    agent1.set_remote_username(agent2.local_username());
    agent1.set_remote_password(agent2.local_password());

    std::cout << "Agent1 is connecting ...\n";
    scope.spawn(stdexec::starts_on(sched, agent1.connect()) | utils::ignore());

    co_await (asioice::utils::on_scope_empty(scope) |
              stdexec::continues_on(sched));

    bool agent1_connected = agent1.state() == agent_state_t::CONNECTED;
    bool agent2_connected = agent2.state() == agent_state_t::CONNECTED;
    if (agent1_connected && agent2_connected) {
        std::cout << "Connect success\n";
        auto np1 = agent1.nominated_pairs();
        auto np2 = agent2.nominated_pairs();
        std::cout << "\nAgent1's nominated pairs:\n";
        for (const auto &p : np1) {
            std::cout << p->to_string() << '\n';
        }
        std::cout << "\nAgent2's nominated pairs:\n";
        for (const auto &p : np2) {
            std::cout << p->to_string() << '\n';
        }
    } else {
        std::cout << "Agent1 connect "
                  << (agent1_connected ? "success, " : "failed, ")
                  << "agent2 connect "
                  << (agent2_connected ? "success\n" : "failed\n");
        co_return;
    }
    std::tuple<std::tuple<std::error_code>, std::tuple<std::error_code>>
        dtls_handshake_res = co_await stdexec::when_all(
            dtls_client->async_handshake(DtlsTransport::handshake_type::client),
            dtls_server->async_handshake(
                DtlsTransport::handshake_type::server));
    if (std::get<0>(std::get<0>(dtls_handshake_res)) != std::error_code{} ||
        std::get<0>(std::get<1>(dtls_handshake_res)) != std::error_code{}) {
        std::cout << "DTLS handshake failed\n";
    } else {
        std::cout << "DTLS handshake success\n";
    }

    sctp_server->start();
    sctp_client->start();
    std::tuple<std::tuple<bool>, std::tuple<bool>> sctp_connect_res =
        co_await stdexec::when_all(sctp_client->connect(),
                                   sctp_server->accept());
    if (!std::get<0>(std::get<0>(sctp_connect_res)) ||
        !std::get<0>(std::get<1>(sctp_connect_res))) {
        std::cout << "SCTP connect failed\n";
    } else {
        std::cout << "SCTP connect success\n";
    }

    DataChannelManager dmgr_client(sctp_client, true);
    DataChannelManager dmgr_server(sctp_server, false);

    dmgr_server.on_remote_channel([&scope](std::shared_ptr<DataChannel> ch) {
        std::cout << "Server got new datachannel: " << ch->label() << '\n';
        scope.spawn([](auto ch) -> asioice::task<void> {
            std::cout << "Waiting for data from client...\n";
            while (ch->is_open()) {
                data_channel_message msg = co_await ch->read();
                bool sent = co_await ch->send_text(std::string_view{
                    (const char *)msg.data.data(), msg.data.size()});
                if (!sent) {
                    std::cout << "Sent response failed\n";
                    co_return;
                }
            }
        }(std::move(ch)));
    });

    dmgr_client.start();
    dmgr_server.start();

    std::shared_ptr<DataChannel> channel =
        co_await dmgr_client.create_data_channel("test_channel");

    scope.spawn([](DataChannel &ch, auto &scope) -> asioice::task<void> {
        utils::scope_guard on_exit{
            [&scope]() noexcept { scope.request_stop(); }};
        std::string msg;
        while (true) {
            std::cout << ">>>";
            msg = co_await async_cin(ch.get_executor());
            if (msg == "quit") {
                bool closed = co_await ch.close();
                if (closed)
                    std::cout << "Channel closed\n";
                else
                    std::cout << "Channel failed to close\n";
                co_return;
            }
            auto sent = co_await ch.send_text(msg);
            if (!sent) {
                std::cerr << "Send failed\n";
                co_return;
            }
            data_channel_message echo = co_await ch.read();
            std::cout << std::string_view{(const char *)echo.data.data(),
                                          echo.data.size()}
                      << '\n';
        }
    }(*channel, scope));

    co_await (asioice::utils::on_scope_empty(scope) |
              stdexec::continues_on(sched));
} catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << '\n';
    co_return;
}

void gathering_test(int num) {
    asioice::net::io_context ctx;
    exec::start_detached(stdexec::starts_on(asioice::utils::scheduler{ctx},
                                            gather_task(ctx, num)));
    ctx.run();
}

int main(int argc, char *argv[]) {
    gathering_test(argc > 1 ? std::atoi(argv[1]) : 100);
}