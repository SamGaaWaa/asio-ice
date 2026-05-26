#include "sctp_transport.hpp"
#include "socket_transport.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/ip/udp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/ip/udp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <exec/start_detached.hpp>

#include <iostream>
#include <ranges>
#include <algorithm>

void ping_pong(size_t n) {
    using namespace asioice;

    net::io_context ctx;

    net::ip::udp::socket client_sock{ctx.get_executor()};
    client_sock.open(net::ip::udp::v4());
    client_sock.bind(
        net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    net::ip::udp::socket server_sock{ctx.get_executor()};
    server_sock.open(net::ip::udp::v4());
    server_sock.bind(
        net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    client_sock.connect(server_sock.local_endpoint());
    server_sock.connect(client_sock.local_endpoint());

    auto client_transport =
        std::make_shared<datagram_transport<net::ip::udp::socket>>(
            std::move(client_sock));
    auto server_transport =
        std::make_shared<datagram_transport<net::ip::udp::socket>>(
            std::move(server_sock));

    client_transport->start();
    server_transport->start();

    using SctpTransport =
        sctp::transport<datagram_transport<net::ip::udp::socket>>;
    SctpTransport sctp_client{std::move(client_transport)};
    SctpTransport sctp_server{std::move(server_transport)};
    sctp_client.start();
    sctp_server.start();

    auto client_coro = [](SctpTransport client, size_t n) -> task<void> {
        bool connected = co_await client.connect();
        if (!connected) {
            std::cerr << "Connect failed\n";
            co_return;
        }
        std::cout << "Client connected\n";

        net::steady_timer timer{client.get_executor()};
        std::string data = "Hello exsctp.";
        for (size_t i = 0; i < n; ++i) {
            exsctp::message msg{0, 0,
                                std::span<const uint8_t>{
                                    (const uint8_t *)data.data(), data.size()}};
            bool ret = co_await client.send(msg, exsctp::send_options{});
            if (!ret) {
                std::cerr << "Client send failed\n";
                co_return;
            }
            std::cout << "Client sent " << data.size() << " bytes\n";
            dcsctp::DcSctpMessage echo = co_await client.read();
            if (!std::ranges::equal(
                    echo.payload(),
                    std::span<const uint8_t>{(const uint8_t *)data.data(),
                                             data.size()})) {
                std::cerr << "Invalid message\n";
                co_return;
            }
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(asio2exec::use_sender);
        }
        co_await client.shutdown();
    };
    auto server_coro = [](SctpTransport server, size_t n) -> task<void> {
        bool connected = co_await server.accept();
        if (!connected) {
            std::cerr << "Connect failed\n";
            co_return;
        }
        std::cout << "Server connected\n";

        net::steady_timer timer{server.get_executor()};
        for (size_t i = 0; i < n; ++i) {
            dcsctp::DcSctpMessage data = co_await server.read();
            std::cout << "Server read " << data.payload().size() << " bytes\n";
            exsctp::message msg{0, 0, data.payload()};
            bool ret = co_await server.send(msg, exsctp::send_options{});
            if (!ret) {
                std::cerr << "Server send failed\n";
                co_return;
            }
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(asio2exec::use_sender);
        }
        co_await server.shutdown();
    };

    asio2exec::scheduler sched{ctx};
    exec::start_detached(
        stdexec::starts_on(sched, client_coro(std::move(sctp_client), n)));
    exec::start_detached(
        stdexec::starts_on(sched, server_coro(std::move(sctp_server), n)));

    ctx.run();
}

int main(int argc, char **argv) {
    ping_pong(argc > 1 ? std::atoi(argv[1]) : 10);
}