#include "config.hpp"
#include "scope_guard.hpp"
#include "socket_transport.hpp"
#include "stun_client.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/buffer.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"

#include <exec/async_scope.hpp>

#include <iostream>
#include <vector>

void udp_request_test() {
    using namespace ice;

    asio2exec::asio_context asio_thread;
    asio_thread.start();

    auto &ctx = asio_thread.get_executor();

    net::ip::udp::resolver resolver(ctx);
    auto resolve_result = resolver.resolve("14.29.112.241", "20002");
    if (resolve_result.empty()) {
        std::cerr << "Resolve error\n";
        return;
    }
    const auto &server_ep = resolve_result.begin()->endpoint();
    std::cout << "STUN server: " << server_ep.address().to_string() << ':'
              << server_ep.port() << '\n';

    auto transport = std::make_shared<datagram_transport<net::ip::udp::socket>>(
        ctx, ctx, net::ip::udp::v4());
    transport->socket().bind(net::ip::udp::endpoint(net::ip::udp::v4(), 0));
    // auto protocol = std::make_shared<
    //     stun_protocol<datagram_transport<net::ip::udp::socket>, true>>(
    //     ctx, transport);

    transport->start();

    stun::client<datagram_transport<net::ip::udp::socket>, true> client(ctx);

    auto request_coro = [&]() -> ice::task<void> {
        stun::message req;
        req.method = stun::method_t::STUN_METHOD_BINDING;
        req.cls = stun::class_t::STUN_CLASS_REQUEST;
        req.use_fingerprint(true);
        req.fill_random_transaction_id();

        stun::message resp;
        net::ip::udp::endpoint resp_from;
        auto success = co_await client.request(*transport, server_ep, req,
                                               resp_from, resp, 3);
        if (!success) {
            std::cerr << "Request error\n";
            co_return;
        }
        std::cout << "Received response from " << resp_from.address() << ':'
                  << resp_from.port() << '\n';
        std::cout << resp.to_string() << '\n';
    };

    asio2exec::scheduler sched{ctx};
    stdexec::sync_wait(stdexec::starts_on(sched, request_coro()));

    std::cout << "Test client.stop()\n";
    exec::async_scope scope;
    net::steady_timer timer{ctx, std::chrono::seconds(10)};
    scope.spawn(stdexec::starts_on(sched, request_coro()));
    scope.spawn(stdexec::starts_on(
        sched, timer.async_wait(asio2exec::use_sender) |
                   stdexec::then([&](auto) { client.stop(); })));
    stdexec::sync_wait(scope.on_empty());
    std::cout << "Finish\n";
}

void tcp_request_test() {
    // using namespace ice;

    // asio2exec::asio_context asio_thread;
    // asio_thread.start();

    // auto &ctx = asio_thread.get_executor();

    // net::ip::tcp::resolver resolver(ctx);
    // auto resolve_result = resolver.resolve("0.0.0.0", "13478");
    // if (resolve_result.empty()) {
    //     std::cerr << "Resolve error\n";
    //     return;
    // }
    // const auto &server_ep = resolve_result->endpoint();
    // std::cout << "STUN server: " << server_ep.address().to_string() << ':'
    //           << server_ep.port() << '\n';

    // net::ip::tcp::socket sock(ctx, net::ip::tcp::v4());
    // sock.bind(net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
    // sock.connect(server_ep);
    // stun::client<net::ip::tcp::socket> client(ctx, sock);

    // auto recv_coro = [&]() -> ice::task<void> {
    //     char buf[8];
    //     std::vector<char> tmp_buf;
    //     while (true) {
    //         auto [err, n] = co_await sock.async_read_some(
    //             net::buffer(buf, sizeof(buf)), asio2exec::use_sender);
    //         if (err) {
    //             std::cerr << "Receive error: " << err.message() << '\n';
    //             co_return;
    //         }
    //         if (n == 0) {
    //             std::cerr << "Disconnected\n";
    //             co_return;
    //         }
    //         std::cout << "Received " << n << " bytes\n";

    //         tmp_buf.insert(tmp_buf.end(), buf, buf + n);
    //         if (!client.dispatch(tmp_buf.data(), tmp_buf.size())) {
    //             if (tmp_buf.size() > 16 * 1024) {
    //                 std::cerr << "Dispatch error\n";
    //                 co_return;
    //             }
    //             continue;
    //         }
    //         tmp_buf.clear();
    //     }
    // };

    // auto request_coro = [&]() -> ice::task<void> {
    //     stun::message req;
    //     req.method = stun::method_t::STUN_METHOD_BINDING;
    //     req.cls = stun::class_t::STUN_CLASS_REQUEST;
    //     req.use_fingerprint(true);
    //     req.fill_random_transaction_id();

    //     stun::message resp;
    //     auto success = co_await client.request(req, resp);
    //     if (!success) {
    //         std::cerr << "Request error\n";
    //         co_return;
    //     }
    //     std::cout << "Received response: " << resp.to_string() << '\n';
    // };

    // asio2exec::scheduler sched{ctx};
    // auto work =
    //     stdexec::when_all(recv_coro(), request_coro() | stdexec::let_value([]
    //     {
    //                                        return stdexec::just_stopped();
    //                                    }));
    // stdexec::sync_wait(
    //     stdexec::starts_on(sched, std::move(work) |
    //     stdexec::into_variant()));

    // std::cout << "Test client.stop()\n";
    // exec::async_scope scope;
    // net::steady_timer timer{ctx, std::chrono::seconds(10)};
    // scope.spawn(stdexec::starts_on(sched, request_coro()));
    // scope.spawn(stdexec::starts_on(
    //     sched, timer.async_wait(asio2exec::use_sender) |
    //                stdexec::then([&](auto) { client.stop(); })));
    // stdexec::sync_wait(scope.on_empty());

    // std::cout << "Finished\n";
}

int main(int argc, char *argv[]) {
    udp_request_test();
    tcp_request_test();
}