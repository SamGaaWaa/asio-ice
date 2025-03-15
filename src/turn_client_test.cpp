#include "config.hpp"
#include "scope_guard.hpp"
#include "turn_client.hpp"

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

void test() {
    using namespace ice;

    net::io_context ctx;

    const net::ip::udp::endpoint server_ep(net::ip::make_address("127.0.0.1"),
                                           13478);
    std::cout << "TURN server: " << server_ep.address().to_string() << ':'
              << server_ep.port() << '\n';

    std::shared_ptr<turn::client<net::ip::udp::socket>> client{};
    {
        net::ip::udp::socket sock(ctx, net::ip::udp::v4());
        sock.bind(net::ip::udp::endpoint(net::ip::udp::v4(), 0));
        client = std::make_shared<turn::client<net::ip::udp::socket>>(
            ctx, std::move(sock), server_ep);
    }
    auto recv_coro = [&]() -> ice::task<void> {
        char buf[2048];
        while (true) {
            net::ip::udp::endpoint ep;
            auto [err, n] = co_await client->socket().async_receive_from(
                net::buffer(buf, sizeof(buf)), ep, asio2exec::use_sender);
            if (err) {
                std::cerr << "Receive error: " << err.message() << '\n';
                co_return;
            }
            std::cout << "Received " << n << " bytes from "
                      << ep.address().to_string() << ':' << ep.port() << '\n';
            auto msg = std::make_unique<stun::message>();
            if (!msg->parse(buf, n) || !msg->is_response())
                continue;
            if (ep != server_ep) {
                std::cerr << "Unexpected response from "
                          << ep.address().to_string() << ':' << ep.port()
                          << '\n';
                continue;
            }
            if (!client->dispatch(std::move(msg))) {
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
        auto resp = co_await client->request(req, std::chrono::seconds(10), 3);
        if (!resp) {
            std::cerr << "Request error\n";
            co_return;
        }
        std::cout << "Resp:\n" << resp->to_string() << '\n';
    };

    asio2exec::scheduler sched{ctx};
    auto work =
        stdexec::when_all(recv_coro(), request_coro() | stdexec::let_value([] {
                                           return stdexec::just_stopped();
                                       }));
    stdexec::start_detached(stdexec::starts_on(sched, std::move(work)));
    ctx.run();
}

int main(int argc, char *argv[]) { test(); }