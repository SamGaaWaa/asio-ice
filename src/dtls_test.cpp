#include <algorithm>
#include <iostream>

#include "config.hpp"
#include "dtls_transport.hpp"
#include "socket_transport.hpp"
#include "detached_with_data.hpp"

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

const char *server_crt = R"(-----BEGIN CERTIFICATE-----
MIID1zCCAr+gAwIBAgIUVO/Ug0WrVEZ+y/wpbYHoK+xr6HAwDQYJKoZIhvcNAQEL
BQAwezELMAkGA1UEBhMCQ04xEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJc2FtZ2Fhd2FhMSAw
HgYJKoZIhvcNAQkBFhFzYW1nYWF3YWFAMTYzLmNvbTAeFw0yNTExMjkxMzE2MTZa
Fw0yNjExMjkxMzE2MTZaMHsxCzAJBgNVBAYTAkNOMRMwEQYDVQQIDApTb21lLVN0
YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMM
CXNhbWdhYXdhYTEgMB4GCSqGSIb3DQEJARYRc2FtZ2Fhd2FhQDE2My5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx0FOMxYofPi4QcxsL4tjnx3ap
CGhLleOIvCJGIlOBaMa067vsVYT7IKrViAUaT6CUIMtlPHA43HLqBDS5EaFJKUea
2oWGekJAmbrRJcnWbEO0dZ+dtp4l7pdC3x8jxqVA2jJN5aXRQ+P8y7CTQH0llEnd
/Btc3Pyf3cnuNEoAD+EtnsQdXDRVv8ADjEcZOQaqco/i5TwYu3HtFVnt6+/R5kVm
O3ZUZiCa7u5sCfo3SleNd2elhn/TOTmhhizMeYfq22GvYQ38KkkwrPggX7nalC1s
zVMUPRs0ZfoKOe0F0Zo6yHbBvs3vZwX+cdZc2fSmydXVqIkHJAYuzE+QUCJLAgMB
AAGjUzBRMB0GA1UdDgQWBBRHsg0+SXLM20W3F6ZnEzmdsl5ShjAfBgNVHSMEGDAW
gBRHsg0+SXLM20W3F6ZnEzmdsl5ShjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQBgwmiAQ16w2TEK8YrUv/ErCorvih5CO/ZkBCs5oDD8Bk+QGx3l
m4M/Nhb278HkWtgXz3LSKhqELRpArtF9xgy3j8eFAEpTb2By0/zbWa7gyifynICC
RIYDI7JXColuotDQDcVTRrIxEUadgq2sFHvbqLx4qWgiGaRpzym6610m0FutwSJi
k7q06eIXEY2O2+4F5Yeo36cs2wJnIZNC1Gm3I/SRZDURw4TFrFL2BZoFw8sHcF0y
Fl4Mg1e0Qm5jvJN91nOvYym5uIziBwgujQBE8A9IyW0uc9T8QNcLsa3BurllkAE0
JLXD2DHy6t4W9twktrhoR53zJuuqgnPMmTQQ
-----END CERTIFICATE-----)";

const char *server_key = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx0FOMxYofPi4Q
cxsL4tjnx3apCGhLleOIvCJGIlOBaMa067vsVYT7IKrViAUaT6CUIMtlPHA43HLq
BDS5EaFJKUea2oWGekJAmbrRJcnWbEO0dZ+dtp4l7pdC3x8jxqVA2jJN5aXRQ+P8
y7CTQH0llEnd/Btc3Pyf3cnuNEoAD+EtnsQdXDRVv8ADjEcZOQaqco/i5TwYu3Ht
FVnt6+/R5kVmO3ZUZiCa7u5sCfo3SleNd2elhn/TOTmhhizMeYfq22GvYQ38Kkkw
rPggX7nalC1szVMUPRs0ZfoKOe0F0Zo6yHbBvs3vZwX+cdZc2fSmydXVqIkHJAYu
zE+QUCJLAgMBAAECgf9EUq5ygmO64cuvQiTmlvbSXMmqXLtQC4PAIAFxz0dG4TdW
xLUSzYUxxjDvQdSR+sJsBk/+4w+RMBKRPz+tmKmtSEjdYjv9RXRixIz7etZxHrEH
WV4VIg3Vp4ru/FVHlIyEeGPb3/LffmFXuMptH5Yp4updA6yQ+Yv2JdOLAJ2QrCf+
yY7hTQN+u9yvsgoGeb5hpssN0zxGRqzWIYip2zbJ8JlsN46N7tDAvN+SUbtPcREY
U7S5MF70DJ4n9LmWSl1EAmo4VI9T5wrncgsJU8FiTqaiYPD4bagheTAxoa4Zwcqn
yNx6c8x0uJFXxPbLMzY7CP1nOSL6pDBFuiXmB9ECgYEA9fd9HRZPilId6UDRUAD8
DsYydwVHzwwGE+2zN56+jFwqMIB+Pzm93ftNuI0fYTWqt2FzJYlW7On4gbhuIaPL
rzbj3BPbGHJsepF1oeaEHsOwu+sWCns6myIRPOjHUkJkTB72pspXVGuiEXc70co/
onZpO9KFSoSyI0KJPLB2URsCgYEAuREmMrGIpYONTdD7LkzxqcE3OlY8o+Bvk9Y/
bKsogJPImsOEXDiGrfh/OQ5jWHlSTdZS2fcoIM+yFuNZluNphuzFFXMREnLDheh2
44Ci+qi54sf+TxAcMcF88QF41OOaAG9VzYwPDJ8hoSsouiZulZnUiI/8cyk8chyg
tfwZtpECgYEAteuOhezyd4O0y8g9B8cyplrBCHbHXcOu2x575y9qD7Y7HhRrS6gR
XhV4rn7yLpva4DcbSzABMsj6HDekfQ0AoV8fuK6W5cX7pcvgDRbJsVdbaCG/85Ch
EAxqY3pnsdeZBxP/qe0OGkphXDmr7MaBuk+KFczm+O6cMqgLiO+bEvECgYEAt4W4
GYFQfsIL+GULEYkgBTUj7WfjTqecPkCyOLMqwQbMYh0NPt6XQCIzF4ObJPt6kNG+
64Nbed49PtFJ4IW3+iMF9hVbkq3YEwzKCSVheaykWa32FLVnIDg+DElnZ8Yky9Wc
gu8nZV7Q3KCODLtb4mLgDmSq9hCobojRHmbXoOECgYEA718z7tBoKDfyPFTMbCOc
DlXC3z5zAK2XUB1+92EXBDXK45yOJBQU/l1MslQMjMaIAjrAh71uGRJ3kQIwGKKy
tDe4vkRzWzwq8iKb7Q+IbzXif1GilqSHJ04T0bMFw1r+3TViFHQIi2x3ILvEkBGm
h/AwPbciuIqmBgK4zkXXen8=
-----END PRIVATE KEY-----)";

int load_cert_and_key_from_str(SSL_CTX *ctx, const char *cert_pem,
                               const char *key_pem) {
    BIO *bio_cert = NULL;
    BIO *bio_key = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;

    bio_cert = BIO_new_mem_buf((void *)cert_pem, -1); // -1 表示自动计算长度
    if (!bio_cert)
        goto err;

    cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL);
    if (!cert)
        goto err;

    bio_key = BIO_new_mem_buf((void *)key_pem, -1);
    if (!bio_key)
        goto err;

    pkey = PEM_read_bio_PrivateKey(bio_key, NULL, NULL, NULL);
    if (!pkey)
        goto err;

    if (SSL_CTX_use_certificate(ctx, cert) <= 0)
        goto err;
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
        goto err;

    if (!SSL_CTX_check_private_key(ctx))
        goto err;

    X509_free(cert);
    EVP_PKEY_free(pkey);
    BIO_free(bio_cert);
    BIO_free(bio_key);
    return 1;
err:
    ERR_print_errors_fp(stderr);
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (bio_cert)
        BIO_free(bio_cert);
    if (bio_key)
        BIO_free(bio_key);
    return 0;
}

asioice::task<void> server_coro(asioice::net::io_context &io_ctx,
                                const char *crt, const char *key) {
    using namespace asioice;
    using DtlsTransport =
        ssl::dtls_transport<datagram_transport<net::ip::udp::socket>>;

    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        co_return;
    }
    utils::scope_guard ctx_guard([&]() noexcept { SSL_CTX_free(ctx); });

    if (!load_cert_and_key_from_str(ctx, crt, key)) {
        std::cerr << "load_cert_and_key_from_str failed\n";
        co_return;
    }

    net::ip::udp::socket sock{io_ctx};
    sock.open(net::ip::udp::v4());
    sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"),
                                     SERVER_PORT));

    net::ip::udp::endpoint client_ep{net::ip::make_address("127.0.0.1"),
                                     CLIENT_PORT};
    sock.connect(client_ep);

    auto sock_transport =
        std::make_shared<datagram_transport<net::ip::udp::socket>>(
            io_ctx, std::move(sock));

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        co_return;
    }
    utils::scope_guard ssl_guard([&]() noexcept { SSL_free(ssl); });

    SSL_set_accept_state(ssl);

    DtlsTransport dtls_server{sock_transport, ssl};
    ssl_guard.dismiss();

    sock_transport->start();
    if (auto ec = co_await dtls_server.async_handshake(
            DtlsTransport::handshake_type::server);
        ec) {
        std::cerr << "DTLS accept error: " << ec.message() << '\n';
        co_return;
    }
    std::cout << "DTLS accept completed\n";

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
            net::steady_timer timer{io_ctx, std::chrono::seconds(5)};
            co_await timer.async_wait(asio2exec::use_sender);
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

    net::io_context io_ctx;
    exec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{io_ctx},
                           server_coro(io_ctx, server_crt, server_key)));

    SSL_CTX *ctx;
    SSL *ssl;

    net::ip::udp::socket sock{io_ctx};
    sock.open(net::ip::udp::v4());
    sock.bind(net::ip::udp::endpoint(net::ip::make_address("127.0.0.1"),
                                     CLIENT_PORT));

    net::ip::udp::endpoint server_ep{net::ip::make_address("127.0.0.1"),
                                     SERVER_PORT};
    sock.connect(server_ep);

    auto sock_transport =
        std::make_shared<datagram_transport<net::ip::udp::socket>>(
            io_ctx, std::move(sock));

    ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    utils::scope_guard ctx_guard([&]() noexcept { SSL_CTX_free(ctx); });

    ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    utils::scope_guard ssl_guard([&]() noexcept { SSL_free(ssl); });

    SSL_set_connect_state(ssl);

    DtlsTransport dtls_client{sock_transport, ssl};
    ssl_guard.dismiss();

    auto work = [&]() -> asioice::task<void> {
        sock_transport->start();
        auto ec = co_await dtls_client.async_handshake(
            DtlsTransport::handshake_type::client);
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

    asio2exec::scheduler sched{io_ctx};
    exec::start_detached(stdexec::starts_on(
        sched, exec::finally(work(), stdexec::just() | stdexec::then([&] {
                                         dtls_client.close();
                                         sock_transport->stop();
                                     }))));
    io_ctx.run();
    std::cout << "Finish\n";
    return 0;
}