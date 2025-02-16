#include "config.hpp"
#include "scope_guard.hpp"
#include "stun_client.hpp"

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST
#include <boost/asio/buffer.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"

#include <iostream>

void request_test() {
    using namespace ice;

    net::io_context ctx;

    net::ip::udp::resolver resolver(ctx);
    auto resolve_result = resolver.resolve("0.0.0.0", "13478");
    if (resolve_result.empty()) {
        std::cerr << "Resolve error\n";
        return;
    }
    const auto &server_ep = resolve_result->endpoint();
    std::cout << "STUN server: " << server_ep.address().to_string() << ':'
              << server_ep.port() << '\n';

    net::ip::udp::socket sock(ctx, net::ip::udp::v4());
    auto client = std::make_shared<stun::client>(ctx, sock);

    auto recv_coro = [&]() -> inline_task<void> {
        char buf[2048];
        while (true) {
            net::ip::udp::endpoint ep;
            auto [err, n] = co_await sock.async_receive_from(
                net::buffer(buf, sizeof(buf)), ep, asio2exec::use_sender);
            if (err) {
                std::cerr << "Receive error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Received " << n << " bytes from "
                      << ep.address().to_string() << ':' << ep.port() << '\n';
            if (!client->dispatch(ep, buf, n)) {
                std::cerr << "Dispatch error\n";
                co_return;
            }
        }
    };

    auto request_coro = [&]() -> inline_task<void> {
        utils::scope_guard on_exit([&]() noexcept { client->stop(); });
        auto req = std::make_unique<stun::message>();
        req->method = stun::method_t::STUN_METHOD_BINDING;
        req->cls = stun::class_t::STUN_CLASS_REQUEST;
        req->use_fingerprint(true);
        req->transaction_id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        auto [resp, from] = co_await client->request(
            server_ep, std::move(req), std::chrono::milliseconds(1000), 3);
        if (!resp) {
            std::cerr << "Request error\n";
            co_return;
        }
        std::cout << "Received response from " << from.address() << ':'
                  << from.port() << '\n';
        std::cout << resp->to_string() << '\n';
    };

    asio2exec::scheduler_t sched{ctx};
    auto work =
        stdexec::when_all(recv_coro(), request_coro() | stdexec::let_value([] {
                                           return stdexec::just_stopped();
                                       }));
    stdexec::start_detached(stdexec::starts_on(sched, std::move(work)));
    ctx.run();
}

int main(int argc, char *argv[]) { request_test(); }