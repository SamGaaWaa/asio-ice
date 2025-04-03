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
            ctx, std::move(sock), server_ep);
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
        bool success = co_await client->request(req, resp_from, resp,
                                                std::chrono::seconds(10), 3);
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
            ctx, std::move(sock), server_ep);
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
    auto allocate_coro = [&]() -> ice::task<void> {
        stun::message req;

        // The client MUST include a REQUESTED-TRANSPORT attribute in the
        // request.
        req.requested_transport = true;

        // If the client wishes the server to initialize the time-to-expiry
        // field of the allocation to some value other than the default
        // lifetime, then it MAY include a LIFETIME attribute specifying its
        // desired value.
        req.lifetime = 10 * 60;

        req.dont_fragment = true;

        req.method = stun::method_t::STUN_METHOD_ALLOCATE;
        req.cls = stun::class_t::STUN_CLASS_REQUEST;
        req.use_fingerprint(true);
        req.fill_random_transaction_id();

        stun::message resp;
        net::ip::udp::endpoint resp_from;
        bool success = co_await client->request(req, resp_from, resp,
                                                std::chrono::seconds(10), 3);
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
        stdexec::when_all(recv_coro(), allocate_coro() | stdexec::let_value([] {
                                           return stdexec::just_stopped();
                                       }));
    stdexec::start_detached(stdexec::starts_on(sched, std::move(work)));
    ctx.run();
}

int main(int argc, char *argv[]) {
    // request_test();
    allocate_test();
}