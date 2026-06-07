#include "config.hpp"
#include "mdns.hpp"

#if CPPMDNS_USE_BOOST_ASIO
#include <boost/asio.hpp>
#define ASIO_TO_EXEC_USE_BOOST
#else
#include <asio.hpp>
#endif
#include "asio2exec.hpp"

#include <exec/when_any.hpp>
#include <exec/start_detached.hpp>

#include <iostream>

namespace ex = stdexec;
using namespace asio2exec;

void mdns_query_test() {
    mdns::net::io_context ctx;
    asio2exec::scheduler sched{ ctx };

    mdns::server server{ ctx.get_executor() };
    auto f = server.query("pion-test.local") |
            ex::then([&](const std::expected<std::string, std::error_code>& ip) {
                std::cout << "Result: " << ip.value() << '\n';
                server.stop();
            });
    exec::start_detached(ex::starts_on(sched, std::move(f)));
    ctx.run();
}

void mdns_publish_test() {
    mdns::net::io_context ctx;
    asio2exec::scheduler sched{ ctx };
    mdns::net::steady_timer timer(ctx);

    timer.expires_after(std::chrono::seconds(30));

    mdns::server server{ ctx.get_executor() };
    auto f = server.publish("192.168.0.4");
    auto timeout = timer.async_wait(asio2exec::use_sender);
    exec::start_detached(
        ex::when_all(
            ex::starts_on(sched, std::move(f) | ex::then([](auto ret) {
                if (ret) {
                    std::cout << "Publish as name: " << *ret << '\n';
                } else {
                    std::cout << "Publish failed: " << ret.error().message();
                }
            })),
            ex::starts_on(sched, std::move(timeout)) | ex::then([&](auto) { server.stop(); })
        )
    );
    ctx.run();
}

int main() {
    try {
        // mdns_query_test();
        mdns_publish_test();
    }
    catch (const std::exception& e) {
        std::cout << "Exception:" << e.what() << '\n';
    }
}