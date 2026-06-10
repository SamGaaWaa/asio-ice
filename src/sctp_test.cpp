#include "asioice/sctp_transport.hpp"
#include "asioice/socket_transport.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
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
    using UdpSocket =
        utils::use_sender_t::as_default_on_t<net::ip::udp::socket>;
    static_assert(UniqueAsyncPacketConnectionTransport<UdpSocket>);

    net::io_context ctx;

    auto client_sock = std::make_shared<UdpSocket>(ctx);
    client_sock->open(net::ip::udp::v4());
    client_sock->bind(
        net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    auto server_sock = std::make_shared<UdpSocket>(ctx);
    server_sock->open(net::ip::udp::v4());
    server_sock->bind(
        net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    client_sock->connect(server_sock->local_endpoint());
    server_sock->connect(client_sock->local_endpoint());

    using SctpTransport = sctp::transport<UdpSocket>;
    SctpTransport sctp_client{client_sock};
    SctpTransport sctp_server{server_sock};
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
            std::optional<dcsctp::DcSctpMessage> echo = co_await client.read();
            if (!std::ranges::equal(
                    echo->payload(),
                    std::span<const uint8_t>{(const uint8_t *)data.data(),
                                             data.size()})) {
                std::cerr << "Invalid message\n";
                co_return;
            }
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(utils::use_sender);
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
            std::optional<dcsctp::DcSctpMessage> data = co_await server.read();
            if (!data) {
                std::cerr << "Server read failed\n";
                co_return;
            }
            std::cout << "Server read " << data->payload().size() << " bytes\n";
            exsctp::message msg{0, 0, data->payload()};
            bool ret = co_await server.send(msg, exsctp::send_options{});
            if (!ret) {
                std::cerr << "Server send failed\n";
                co_return;
            }
            timer.expires_after(std::chrono::seconds(1));
            co_await timer.async_wait(utils::use_sender);
        }
        co_await server.shutdown();
    };

    utils::scheduler sched{ctx};
    exec::start_detached(
        stdexec::starts_on(sched, client_coro(std::move(sctp_client), n)));
    exec::start_detached(
        stdexec::starts_on(sched, server_coro(std::move(sctp_server), n)));

    ctx.run();
}

int main(int argc, char **argv) {
    ping_pong(argc > 1 ? std::atoi(argv[1]) : 10);
}