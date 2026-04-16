#include "config.hpp"
#include "on_scope_empty.hpp"
#include "task.hpp"
#include "stop_when.hpp"
#include "scope_guard.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/signal_set.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/signal_set.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"

#include <iostream>

#include <exec/start_detached.hpp>

asioice::task<void> timeout(asioice::net::io_context &ctx) {
    asioice::net::steady_timer timer(ctx, std::chrono::seconds(60));
    std::cout << "Waiting...\n";
    asioice::utils::scope_guard on_stop(
        []() noexcept { std::cout << "Canceled\n"; });
    auto ec = co_await timer.async_wait(asio2exec::use_sender);
    if (ec)
        throw std::system_error(ec);
    std::cout << "Finish\n";
    on_stop.dismiss();
}

void test() {
    using namespace asioice;

    net::io_context ctx;
    exec::async_scope scope;

    for (int i = 0; i < 100; ++i) {
        scope.spawn(
            stdexec::starts_on(asio2exec::scheduler{ctx}, timeout(ctx)));
    }

    net::steady_timer timer(ctx, std::chrono::seconds(5));
    auto work = utils::stop_when(
        utils::on_scope_empty(scope) | stdexec::upon_stopped([] {
            std::cout << "scope has been requested to stop\n";
        }),
        timer.async_wait(asio2exec::use_sender));

    exec::start_detached(std::move(work));

    ctx.run();
}

int main() { test(); }