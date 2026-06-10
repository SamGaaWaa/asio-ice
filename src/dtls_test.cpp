#include <algorithm>
#include <iostream>

#include "asioice/config.hpp"
#include "asioice/dtls_transport.hpp"
#include "asioice/socket_transport.hpp"
#include "asioice/detail/detached_with_data.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/steady_timer.hpp>
#include <asio/udp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <exec/finally.hpp>
#include <exec/start_detached.hpp>

#define SERVER_PORT 4433
#define CLIENT_PORT 12345
#define MAX_BUFFER 1024

asioice::task<void> server_coro(asioice::net::any_io_executor ex,
                                asioice::ssl::dtls_certificate cert,
                                asioice::ssl::fingerprint client_fp) {
    using namespace asioice;
    using DtlsTransport =
        ssl::dtls_transport<datagram_transport<net::ip::udp::socket>>;

    net::ip::udp::socket sock{ex};
    sock.open(net::ip::udp::v4());
    sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"),
                                     SERVER_PORT));

    net::ip::udp::endpoint client_ep{net::ip::make_address("127.0.0.1"),
                                     CLIENT_PORT};
    sock.connect(client_ep);

    auto sock_transport =
        std::make_shared<datagram_transport<net::ip::udp::socket>>(
            std::move(sock));

    DtlsTransport dtls_server{sock_transport, std::move(cert)};
    dtls_server.set_expected_remote_fingerprint(client_fp);

    sock_transport->start();
    if (auto ec = co_await dtls_server.async_handshake(
            DtlsTransport::handshake_type::server);
        ec) {
        std::cerr << "DTLS accept error: " << ec.message() << '\n';
        co_return;
    }
    std::cout << "DTLS accept completed\n";

    auto remote_fp =
        dtls_server.get_remote_fingerprint(ssl::hash_algorithm::sha256);
    std::cout << "Server's remote fingerprint: " << remote_fp.value << '\n';

    if (auto srtp_material = dtls_server.export_srtp_key_material();
        srtp_material) {
        std::cout << "Server got SRTP material\n";
    }

    std::cout << "Waiting for data from client...\n";
    char buffer[MAX_BUFFER];
    while (true) {
        auto [ec, n] = co_await dtls_server.async_receive(
            net::buffer(buffer, sizeof(buffer) - 1));
        if (ec) {
            std::cout << "Server read error: " << ec.message() << '\n';
            co_return;
        } else if (n > 0) {
            buffer[n] = '\0';
            std::tie(ec, n) =
                co_await dtls_server.async_send(net::buffer(buffer, n));
            if (ec || n == 0) {
                std::cout << "Sent response failed\n";
                co_return;
            }
        } else if (n == 0) {
            std::cout << "Client closed the connection\n";
            // test fast shutdown
            net::steady_timer timer{ex, std::chrono::seconds(5)};
            co_await timer.async_wait(utils::use_sender);
            ec = co_await dtls_server.async_shutdown(false);
            if (ec)
                std::cerr << "Server shutdown failed: " << ec.message() << '\n';
            else
                std::cout << "Server shutdown success\n";
            co_return;
        }
    }
    co_return;
}

int main() {
    using namespace asioice;
    using DtlsTransport =
        ssl::dtls_transport<datagram_transport<net::ip::udp::socket>>;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl::dtls_certificate server_cert, client_cert;

    auto server_fp = server_cert.get_fingerprint(ssl::hash_algorithm::sha256);
    auto client_fp = client_cert.get_fingerprint(ssl::hash_algorithm::sha256);

    std::cout << "Server fingerprint: " << server_fp.value << '\n';
    std::cout << "Client fingerprint: " << client_fp.value << '\n';

    net::io_context io_ctx;
    exec::start_detached(stdexec::starts_on(
        utils::scheduler{io_ctx},
        server_coro(io_ctx.get_executor(), std::move(server_cert), client_fp)));

    net::ip::udp::socket sock{io_ctx.get_executor()};
    sock.open(net::ip::udp::v4());
    sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"),
                                     CLIENT_PORT));

    net::ip::udp::endpoint server_ep{net::ip::make_address("127.0.0.1"),
                                     SERVER_PORT};
    sock.connect(server_ep);

    auto sock_transport =
        std::make_shared<datagram_transport<net::ip::udp::socket>>(
            std::move(sock));

    DtlsTransport dtls_client{sock_transport, std::move(client_cert)};
    dtls_client.set_expected_remote_fingerprint(server_fp);

    auto work = [&]() -> asioice::task<void> {
        sock_transport->start();
        auto ec = co_await dtls_client.async_handshake(
            DtlsTransport::handshake_type::client);
        if (ec) {
            std::cerr << "DTLS connect error: " << ec.message() << '\n';
            co_return;
        }
        std::cout << "DTLS connect success\n";

        auto remote_fp =
            dtls_client.get_remote_fingerprint(ssl::hash_algorithm::sha256);
        std::cout << "Client's remote fingerprint: " << remote_fp.value
                  << '\n';

        if (auto srtp_material = dtls_client.export_srtp_key_material();
            srtp_material) {
            std::cout << "Client got SRTP material\n";
        }

        std::string msg;
        char recv_buf[1024];
        while (true) {
            std::cout << ">>>";
            std::getline(std::cin, msg);
            if (msg == "quit") {
                auto ec = co_await dtls_client.async_shutdown(false);
                if (ec)
                    std::cerr << "Shutdown failed: " << ec.message() << '\n';
                else
                    std::cout << "Shutdown success\n";
                co_return;
            }
            auto [ec, n] = co_await dtls_client.async_send(net::buffer(msg));
            if (ec) {
                std::cerr << "Send failed: " << ec.message() << '\n';
                co_return;
            }
            std::tie(ec, n) = co_await dtls_client.async_receive(
                net::buffer(recv_buf, sizeof(recv_buf)));
            if (ec) {
                std::cerr << "Read failed: " << ec.message() << '\n';
                co_return;
            }
            if (n == 0) {
                std::cerr << "Peer closed\n";
                co_return;
            }
            std::cout << std::string_view{recv_buf, n} << '\n';
        }
    };

    utils::scheduler sched{io_ctx};
    exec::start_detached(stdexec::starts_on(
        sched, exec::finally(work(), stdexec::just() | stdexec::then([&] {
                                         dtls_client.close();
                                         sock_transport->stop();
                                     }))));
    io_ctx.run();
    std::cout << "Finish\n";
    return 0;
}