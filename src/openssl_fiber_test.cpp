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
#include "fiber/spawn.hpp"
#include "fiber/sync_wait.hpp"

#include <exec/task.hpp>

#include <iostream>

using namespace ice;

exec::task<void> test_openssl_fiber(net::io_context &ctx) {
    net::steady_timer timer(ctx, std::chrono::seconds(3));
    co_await fiber::spawn(co_await stdexec::get_scheduler(), [&] {
        std::cout << "Hello World!\n";
        auto work = timer.async_wait(asio2exec::use_sender);
        fiber::sync_wait(std::move(work));
        std::cout << "Finish\n";
    });
}

void test() {
    net::io_context ctx;
    asio2exec::scheduler sched(ctx);
    stdexec::start_detached(stdexec::starts_on(sched, test_openssl_fiber(ctx)));
    ctx.run();
}

int main() { test(); }