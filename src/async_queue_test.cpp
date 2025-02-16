#include "async_queue.hpp"
#include "config.hpp"
#include "inline_task.hpp"

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
namespace ice {
namespace net = boost::asio;
using boost::system::error_code;
} // namespace ice
#else
#include "asio2exec.hpp"
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/io_context.hpp>
#include <asio/use_awaitable.hpp>
#include <system_error>
namespace ice {
namespace net = asio;
using std::error_code;
} // namespace ice
#endif

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <chrono>
#include <iostream>
#include <system_error>

constexpr auto buffer_max_size = 16;

template <class T>
using coro_task =
    exec::__task::basic_task<T, exec::__task::__raw_task_context<T>>;

uint64_t asio_channel_test(int times) {
    using namespace ice;

    net::io_context ctx;
    net::experimental::channel<void(ice::error_code, int)> ch{ctx,
                                                              buffer_max_size};

    uint64_t sum = 0;

    auto reader = [&]() -> net::awaitable<void> {
        for (int i = 0; i < times; ++i) {
            int ret;
            if (!ch.try_receive([&](ice::error_code, int x) { ret = x; }))
                ret = co_await ch.async_receive(net::use_awaitable);
            sum += ret;
        }
    };

    auto writer = [&]() -> net::awaitable<void> {
        for (int i = 1; i <= times; ++i) {
            if (!ch.try_send(ice::error_code{}, i))
                co_await ch.async_send({}, i, net::use_awaitable);
        }
    };

    net::co_spawn(ctx, reader, net::detached);
    net::co_spawn(ctx, writer, net::detached);

    ctx.run();
    return sum;
}

uint64_t async_queue_test(int times) {
    using namespace ice;

    net::io_context ctx;
    asio2exec::scheduler_t sched{ctx};
    async_queue<std::tuple<ice::error_code, int>> q(buffer_max_size);

    uint64_t sum = 0;

    auto reader = [&]() -> coro_task<void> {
        while (true) {
            auto ret = co_await q.async_pop();
            if (!ret)
                co_return;
            sum += std::get<1>(*ret);
        }
    };

    auto writer = [&]() -> coro_task<void> {
        for (int i = 1; i <= times; ++i) {
            while (q.full())
                co_await stdexec::schedule(sched);
            q.push(std::make_tuple(ice::error_code{}, i),
                   [](auto &container) { container.pop_front(); });
        }
        q.close();
        co_return;
    };

    exec::async_scope scope;
    scope.spawn(stdexec::starts_on(sched, reader()));
    scope.spawn(stdexec::starts_on(sched, writer()));

    ctx.run();
    return sum;
}

uint64_t async_queue_with_circular_buffer_test(int times) {
    using namespace ice;

    net::io_context ctx;
    asio2exec::scheduler_t sched{ctx};
    async_queue<std::tuple<ice::error_code, int>,
                boost::circular_buffer<std::tuple<ice::error_code, int>>>
        q(buffer_max_size);

    uint64_t sum = 0;

    auto reader = [&]() -> coro_task<void> {
        while (true) {
            auto ret = co_await q.async_pop();
            if (!ret)
                co_return;
            sum += std::get<1>(*ret);
        }
    };

    auto writer = [&]() -> coro_task<void> {
        for (int i = 1; i <= times; ++i) {
            while (q.full())
                co_await stdexec::schedule(sched);
            q.push(std::make_tuple(ice::error_code{}, i),
                   [](auto &container) { container.pop_front(); });
        }
        q.close();
        co_return;
    };

    exec::async_scope scope;
    scope.spawn(stdexec::starts_on(sched, reader()));
    scope.spawn(stdexec::starts_on(sched, writer()));

    ctx.run();
    return sum;
}

uint64_t async_queue_with_inline_task_test(int times) {
    using namespace ice;

    net::io_context ctx;
    asio2exec::scheduler_t sched{ctx};
    async_queue<std::tuple<ice::error_code, int>> q(buffer_max_size);

    uint64_t sum = 0;

    auto reader = [&]() -> inline_task<void> {
        while (true) {
            auto ret = co_await q.async_pop();
            if (!ret)
                co_return;
            sum += std::get<1>(*ret);
        }
    };

    auto writer = [&]() -> inline_task<void> {
        for (int i = 1; i <= times; ++i) {
            while (q.full())
                co_await stdexec::schedule(sched);
            q.push(std::make_tuple(ice::error_code{}, i),
                   [](auto &container) { container.pop_front(); });
        }
        q.close();
        co_return;
    };

    exec::async_scope scope;
    scope.spawn(stdexec::starts_on(sched, reader()));
    scope.spawn(stdexec::starts_on(sched, writer()));

    ctx.run();
    return sum;
}

int main(int argc, char **argv) {
    int times = argc > 1 ? std::atoi(argv[1]) : 100000000;
    uint64_t sum = 0;

    std::cout << "asio_channel_test\n";
    {
        auto begin = std::chrono::high_resolution_clock::now();
        sum = asio_channel_test(times);
        auto end = std::chrono::high_resolution_clock::now();
        auto total =
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        std::cout << "Result:        " << sum << '\n'
                  << "Total:         " << total.count() << " ns\n"
                  << "Per operation: " << total.count() / times << " ns\n\n";
    }

    std::cout << "async_queue_test\n";
    {
        auto begin = std::chrono::high_resolution_clock::now();
        sum = async_queue_test(times);
        auto end = std::chrono::high_resolution_clock::now();
        auto total =
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        std::cout << "Result:        " << sum << '\n'
                  << "Total:         " << total.count() << " ns\n"
                  << "Per operation: " << total.count() / times << " ns\n\n";
    }

    std::cout << "async_queue_with_circular_buffer_test\n";
    {
        auto begin = std::chrono::high_resolution_clock::now();
        sum = async_queue_with_circular_buffer_test(times);
        auto end = std::chrono::high_resolution_clock::now();
        auto total =
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        std::cout << "Result:        " << sum << '\n'
                  << "Total:         " << total.count() << " ns\n"
                  << "Per operation: " << total.count() / times << " ns\n\n";
    }

    std::cout << "async_queue_with_inline_task_test\n";
    {
        auto begin = std::chrono::high_resolution_clock::now();
        sum = async_queue_with_inline_task_test(times);
        auto end = std::chrono::high_resolution_clock::now();
        auto total =
            std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
        std::cout << "Result:        " << sum << '\n'
                  << "Total:         " << total.count() << " ns\n"
                  << "Per operation: " << total.count() / times << " ns\n\n";
    }
}