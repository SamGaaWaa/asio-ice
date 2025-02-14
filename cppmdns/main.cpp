#include "config.hpp"
#include "mdns.hpp"

#if CPPMDNS_USE_BOOST 
#include <boost/asio.hpp>
#define ASIO_TO_EXEC_USE_BOOST
#else
#include <asio.hpp>
#endif
#include "asio2exec.hpp"

#include "exec/when_any.hpp"

#include <iostream>

namespace ex = stdexec;
using namespace asio2exec;

void mdns_query_test() {
    mdns::net::io_context ctx;
    asio2exec::scheduler_t sched{ ctx };

    mdns::server server{ ctx };
    auto f = server.queryA("pion-test.local") |
            ex::then([&](const std::expected<std::string, std::error_code>& ip) {
                std::cout << "Result: " << ip.value() << '\n';
                server.stop();
            });
    ex::start_detached(ex::starts_on(sched, std::move(f)));
    ctx.run();
}

void mdns_publish_test() {
    mdns::net::io_context ctx;
    asio2exec::scheduler_t sched{ ctx };
    mdns::net::steady_timer timer(ctx);

    timer.expires_after(std::chrono::seconds(30));

    mdns::server server{ ctx };
    auto f = server.publish("pion-test.local", "192.168.0.4");
    auto timeout = timer.async_wait(asio2exec::use_sender);
    ex::start_detached(
        ex::when_all(
            ex::starts_on(sched, std::move(f)),
            ex::starts_on(sched, std::move(timeout)) | ex::then([&](auto) { server.stop(); })
        )
    );
    ctx.run();
}

int main() {
    try {
        mdns_query_test();
        mdns_publish_test();
    }
    catch (const std::exception& e) {
        std::cout << "Exception:" << e.what() << '\n';
    }
}