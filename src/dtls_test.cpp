#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <thread>
#include <algorithm>
#include <iostream>

#include "config.hpp"
#include "dtls_transport.hpp"
#include "socket_transport.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/steady_timer.hpp>
#include <asio/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <exec/finally.hpp>

#define SERVER_PORT 4433
#define CLIENT_PORT 12345
#define MAX_BUFFER 1024

int dtls_server(const char *crt, const char *key) {
    using namespace ice;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    int sock;
    struct sockaddr_in server_addr, client_addr;
    char buffer[MAX_BUFFER];
    int ret;

    ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    utils::scope_guard ctx_guard([&]() noexcept {
        SSL_CTX_free(ctx);
    });

    if (SSL_CTX_use_certificate_file(ctx, crt, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    utils::scope_guard sock_guard([&]() noexcept {
        close(sock);
    });

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    client_addr.sin_port = htons(CLIENT_PORT);

    bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    utils::scope_guard bio_guard([&]() noexcept {
        BIO_free_all(bio);
    });

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &client_addr);

    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    utils::scope_guard ssl_guard([&]() noexcept {
        SSL_free(ssl);
    });

    SSL_set_bio(ssl, bio, bio);
    bio_guard.dismiss();

    std::cout << "Waiting for DTLS handshake...\n";
    ret = SSL_accept(ssl);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    std::cout << "DTLS handshake completed\n";

    std::cout << "Waiting for data from client...\n";
    while (true) {
        ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (ret > 0) {
            buffer[ret] = '\0';
            ret = SSL_write(ssl, buffer, ret);
            if (ret <= 0) {
                std::cout << "Sent response failed\n";
                return -1;
            }
        } else if (ret == 0) {
            std::cout << "Client closed the connection\n";
            // test fast shutdown
            std::this_thread::sleep_for(std::chrono::seconds{10});
            SSL_shutdown(ssl);
            return 0;
        } else {
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    return 0;
}

int main() {
    using namespace ice;
    using DtlsClient = ssl::dtls_transport<datagram_transport<net::ip::udp::socket>>;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    std::thread server_th{dtls_server, "/mnt/d/openSource/asio-ice/clang-build/server.crt", "/mnt/d/openSource/asio-ice/clang-build/server.key"};

    sleep(5);

    net::io_context io_ctx;
    SSL_CTX *ctx;
    SSL *ssl;

    net::ip::udp::socket sock{io_ctx};
    sock.open(net::ip::udp::v4());
    sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"), CLIENT_PORT));
    auto sock_transport = std::make_shared<datagram_transport<net::ip::udp::socket>>(io_ctx, std::move(sock));

    ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    utils::scope_guard ctx_guard([&]() noexcept {
        SSL_CTX_free(ctx);
    });

    net::ip::udp::endpoint server_ep{net::ip::make_address("127.0.0.1"), SERVER_PORT};

    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    utils::scope_guard ssl_guard([&]() noexcept {
        SSL_free(ssl);
    });

    SSL_set_connect_state(ssl);

    DtlsClient dtls_client{sock_transport, server_ep, ssl};
    ssl_guard.dismiss();

    auto work = [&]()-> ice::task<void> {
        sock_transport->start();
        auto ec = co_await dtls_client.async_handshake(DtlsClient::handshake_type::client);
        if (ec) {
            std::cerr << "DTLS connect error: " << ec.message() << '\n';
            co_return;
        }
        std::cout << "DTLS connect success\n";
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
            std::tie(ec, n) = co_await dtls_client.async_receive(net::buffer(recv_buf, sizeof(recv_buf)));
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

    asio2exec::scheduler sched{io_ctx};
    stdexec::start_detached(stdexec::starts_on(
                                sched,
                                exec::finally(work(), stdexec::just() | stdexec::then([&] {
                                    dtls_client.close();
                                    sock_transport->stop();
                                }))
                            ));
    io_ctx.run();
    server_th.join();
    std::cout << "Finish\n";
    return 0;
}