#include "asio2exec.hpp"
#include "config.hpp"
#include "scope_guard.hpp"
#include "turn_client.hpp"

#include <iostream>

void request_test() {
    using namespace ice;

    net::io_context ctx;

    const net::ip::udp::endpoint server_ep(net::ip::make_address("127.0.0.1"),
                                           13478);
    std::cout << "TURN server: " << server_ep.address().to_string() << ':'
              << server_ep.port() << '\n';

    std::unique_ptr<turn::client<net::ip::udp::socket>> client{};
    {
        net::ip::udp::socket sock(ctx, net::ip::udp::v4());
        sock.bind(net::ip::udp::endpoint(net::ip::udp::v4(), 0));
        client = std::make_unique<turn::client<net::ip::udp::socket>>(
            ctx, std::move(sock), server_ep, "samgaawaa", "1234");
    }
    auto recv_coro = [&]() -> ice::task<void> {
        char buf[2048];
        while (true) {
            net::ip::udp::endpoint ep;
            auto [err, n] = co_await client->next_layer().async_receive_from(
                net::buffer(buf, sizeof(buf)), ep, asio2exec::use_sender);
            if (err) {
                std::cerr << "Receive error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Received " << n << " bytes from "
                      << ep.address().to_string() << ':' << ep.port() << '\n';
            if (ep != server_ep) {
                std::cerr << "Unexpected response from "
                          << ep.address().to_string() << ':' << ep.port()
                          << '\n';
                continue;
            }
            if (!client->dispatch(buf, n)) {
                std::cerr << "Dispatch error\n";
                co_return;
            }
        }
    };

    auto request_coro = [&]() -> ice::task<void> {
        utils::scope_guard on_exit([&]() noexcept { client->stop(); });
        stun::message req;
        req.method = stun::method_t::STUN_METHOD_BINDING;
        req.cls = stun::class_t::STUN_CLASS_REQUEST;
        req.use_fingerprint(true);
        req.fill_random_transaction_id();

        stun::message resp;
        net::ip::udp::endpoint resp_from;
        bool success = co_await client->request(req, resp_from, resp, 3);
        if (resp_from != server_ep) {
            std::cerr << "Received response from unknown address: "
                      << resp_from.address() << ':' << resp_from.port() << '\n';
        }
        if (!success) {
            std::cerr << "Request error\n";
            co_return;
        }
        std::cout << "Resp:\n" << resp.to_string() << '\n';
    };

    asio2exec::scheduler sched{ctx};
    auto work =
        stdexec::when_all(recv_coro(), request_coro() | stdexec::let_value([] {
                                           return stdexec::just_stopped();
                                       }));
    stdexec::start_detached(stdexec::starts_on(sched, std::move(work)));
    ctx.run();
}

void allocate_test() {
    using namespace ice;

    std::cout << "Native is "
              << (binary::native_is_big_endian() ? "big endian\n"
                                                 : "little endian\n");
    net::io_context ctx;

    const net::ip::udp::endpoint server_ep(net::ip::make_address("127.0.0.1"),
                                           13478);
    std::cout << "TURN server: " << server_ep.address().to_string() << ':'
              << server_ep.port() << '\n';

    std::unique_ptr<turn::client<net::ip::udp::socket>> client{};
    {
        net::ip::udp::socket sock(ctx, net::ip::udp::v4());
        sock.bind(net::ip::udp::endpoint(net::ip::udp::v4(), 0));
        client = std::make_unique<turn::client<net::ip::udp::socket>>(
            ctx, std::move(sock), server_ep, "samgaawaa", "1234");
    }
    net::ip::udp::socket remote_peer(ctx, net::ip::udp::v4());
    remote_peer.bind(
        net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    auto recv_coro = [&]() -> ice::task<void> {
        char buf[2048];
        while (true) {
            net::ip::udp::endpoint ep;
            auto [err, n] = co_await client->next_layer().async_receive_from(
                net::buffer(buf, sizeof(buf)), ep, asio2exec::use_sender);
            if (err) {
                std::cerr << "Receive error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Received " << n << " bytes from "
                      << ep.address().to_string() << ':' << ep.port() << '\n';
            if (ep != server_ep) {
                std::cerr << "Unexpected response from "
                          << ep.address().to_string() << ':' << ep.port()
                          << '\n';
                continue;
            }
            if (!client->dispatch(buf, n)) {
                std::cerr << "Dispatch error\n";
                // co_return;
            }
        }
    };
    auto allocate_coro = [&]() -> ice::task<void> {
        auto relayed =
            co_await client->create_allocation(std::chrono::seconds(60 * 10));
        if (!relayed) {
            std::cerr << "Allocate failed\n";
            co_return;
        }
        std::cout << "Relayed address: " << relayed->address() << ":"
                  << relayed->port() << '\n';

        auto peer = remote_peer.local_endpoint();
        std::cout << "Creat permission for " << peer.address() << '\n';
        co_await client->create_permission(peer.address());

        std::cout << "\nSending data...\n";
        net::steady_timer timer{ctx};
        std::string data = "Hello, world!";
        while (true) {
            auto [err, n] = co_await client->async_send_to(
                net::const_buffer(data.data(), data.size()), peer);
            if (err) {
                std::cerr << "Send error: " << err.message() << '\n';
            } else {
                std::cout << "Sent " << n << " bytes\n\n";
            }
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(asio2exec::use_sender);
        }
    };
    auto peer_recv_coro = [&]() -> ice::task<void> {
        while (true) {
            char buf[1024] = {};
            net::ip::udp::endpoint relayed;
            auto [err, n] = co_await remote_peer.async_receive_from(
                net::buffer(buf, sizeof(buf)), relayed, asio2exec::use_sender);
            if (err) {
                std::cerr << "Receive error: " << err.message() << '\n';
            } else {
                std::cout << "Received " << n << " bytes from "
                          << relayed.address() << ':' << relayed.port() << ": "
                          << std::string_view{buf, n} << "\n\n";
            }
        }
    };

    asio2exec::scheduler sched{ctx};
    auto work = stdexec::when_all(recv_coro(), peer_recv_coro(),
                                  allocate_coro() | stdexec::let_value([] {
                                      //    return stdexec::just_stopped();
                                      return stdexec::just();
                                  }));
    stdexec::start_detached(stdexec::starts_on(sched, std::move(work)));
    ctx.run();
}

int main(int argc, char *argv[]) {
    // request_test();
    allocate_test();
}