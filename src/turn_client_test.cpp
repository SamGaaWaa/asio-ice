#include "io_buffer2.hpp"
#include "receiver.hpp"
#include "scope_guard.hpp"
#include "socket_transport.hpp"
#include "turn_client.hpp"
#include "candidate_pair.hpp"
// #include "leak_detector.hpp"

#include <iostream>

#include <exec/start_detached.hpp>

using Transport = asioice::datagram_transport<asioice::net::ip::udp::socket>;
using TurnClient = asioice::turn::client<Transport, true>;

void allocate_test(std::size_t epoch_count) {
    using namespace asioice;
    // debug::leak_detector_start();
    // utils::scope_guard stop_leak_detector([]()noexcept {
    // debug::leak_detector_stop(); });

    std::chrono::high_resolution_clock::time_point begin_time, end_time;
    std::size_t total_bytes = 0;
    net::io_context ctx;

    const net::ip::udp::endpoint server_ep(net::ip::make_address("127.0.0.1"),
                                           13478);
    std::cout << "TURN server: " << server_ep.address().to_string() << ':'
              << server_ep.port() << '\n';

    auto transport = std::make_shared<Transport>(
        ctx, ctx, net::ip::udp::endpoint(net::ip::udp::v4(), 0));
    transport->socket().connect(server_ep);
    transport->start();

    stun::transaction_set transactions;

    TurnClient client(transport, server_ep, "samgaawaa", "1234");

    net::ip::udp::socket remote_peer(ctx, net::ip::udp::v4());
    remote_peer.bind(
        net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    auto peer = remote_peer.local_endpoint();
    asioice::candidate remote_c{
        .endpoint = asioice::endpoint(peer.address(), peer.port())};

    asioice::candidate local_c;
    local_c.transport = client.impl().shared_from_this();
    auto cpair = std::make_shared<asioice::candidate_pair>(local_c, remote_c);
    queue_datagram_receiver data_queue(cpair, 16);

    auto allocate_coro = [&]() -> asioice::task<void> {
        auto relayed =
            co_await client.create_allocation(std::chrono::seconds(60 * 10));
        if (!relayed) {
            std::cerr << "Allocate failed\n";
            co_return;
        }
        std::cout << "Relayed address: " << relayed->address() << ":"
                  << relayed->port() << '\n';
        auto ec =
            co_await remote_peer.async_connect(*relayed, asio2exec::use_sender);
        if (ec) {
            std::cerr << "Connect failed: " << ec.message() << '\n';
            co_return;
        }
        std::cout << "Creat channel for " << peer.address() << ':'
                  << peer.port() << '\n';
        if (!co_await client.channel_bind(peer)) {
            std::cerr << "Channel bind failed\n";
            co_return;
        }

        std::cout << "\nSending data...\n";
        net::steady_timer timer{ctx};
        std::string data = "\xcdHello, world!";
        begin_time = std::chrono::high_resolution_clock::now();

        while (true) {
            auto [err, n] = co_await cpair->send(net::buffer(data));
            if (err) {
                std::cerr << "Send error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Sent " << n << " bytes\n";
            auto ret = co_await data_queue.async_pop();
            if (!ret) {
                std::cout << "Stopped\n";
                co_return;
            }
            const auto &[msg, peer] = *ret;
            if (!msg) {
                std::cerr << "Read error\n";
                co_return;
            }
            std::cout << "Echo back " << msg->size() << " bytes: "
                      << std::string_view{(const char *)msg->begin() + 1,
                                          msg->size() - 1}
                      << "\n\n";
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(asio2exec::use_sender);
        }
    };
    auto peer_recv_coro = [&]() -> asioice::task<void> {
        for (int i = 0; i < epoch_count; ++i) {
            char buf[4096];
            net::ip::udp::endpoint relayed;
            std::error_code err;
            std::size_t n;
            std::tie(err, n) = co_await remote_peer.async_receive_from(
                net::buffer(buf), relayed, asio2exec::use_sender);
            if (err) {
                std::cerr << "Receive error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Received " << n << " bytes from \""
                      << relayed.address() << ':' << relayed.port()
                      << "\": " << std::string_view{buf, n} << '\n';
            std::tie(err, n) = co_await remote_peer.async_send_to(
                net::buffer(buf, n), relayed, asio2exec::use_sender);
            if (err) {
                std::cerr << "Send error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Sent back " << n << " bytes to \""
                      << relayed.address() << ':' << relayed.port() << "\"\n";
        }
        end_time = std::chrono::high_resolution_clock::now();
        client.stop();
        transport->stop();
        co_await stdexec::just_stopped();
    };

    asio2exec::scheduler sched{ctx};
    auto work = stdexec::when_all(peer_recv_coro(),
                                  allocate_coro() | stdexec::let_value([&] {
                                      return stdexec::just_stopped() |
                                             stdexec::continues_on(sched);
                                  }));
    exec::start_detached(stdexec::starts_on(sched, std::move(work)));
    ctx.run();

    auto total_time = std::chrono::duration_cast<std::chrono::duration<double>>(
        end_time - begin_time);
    std::cout << "Send " << total_bytes << " bytes in " << total_time.count()
              << " seconds\n"
              << "Speed: " << total_bytes / total_time.count() / 1024 / 1024
              << " MB/s\n";
}

int main(int argc, char *argv[]) {
    allocate_test(argc > 1 ? std::atoi(argv[1]) : 10);
}