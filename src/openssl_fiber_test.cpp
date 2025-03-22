#include <exception>

#include "config.hpp"
#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST
#include <boost/asio/steady_timer.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/steady_timer.hpp>
namespace ice {
namespace net = asio;
}
#endif
#include "asio2exec.hpp"
#include "fiber/condition_variable.hpp"
#include "fiber/run_loop.hpp"
#include "fiber/sender.hpp"
#include "fiber/spawn.hpp"

#include <exec/task.hpp>

#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ice;

exec::task<void> test_openssl_fiber(net::io_context &ctx) {
    net::steady_timer timer(ctx, std::chrono::seconds(3));
    auto sched = co_await stdexec::get_scheduler();
    co_await fiber::spawn(
        sched,
        [&](int) {
            std::cout << "Hello World!\n";
            fiber::run_loop loop;
            auto work = timer.async_wait(asio2exec::use_sender) |
                        stdexec::then([&](auto) { loop.finish(); });
            stdexec::start_detached(
                stdexec::starts_on(loop.get_scheduler(), std::move(work)));
            loop.run();
            std::cout << "Finish\n";
        },
        1);
}

void test() {
    net::io_context ctx;
    asio2exec::scheduler sched(ctx);
    stdexec::start_detached(stdexec::starts_on(sched, test_openssl_fiber(ctx)));
    ctx.run();
}

int main() { test(); }