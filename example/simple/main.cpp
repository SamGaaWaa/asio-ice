#include "asioice.hpp"

#if ASIOICE_USE_BOOST_ASIO
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/udp.hpp>
#else
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ip/udp.hpp>
#endif

#include <iostream>
#include <exec/start_detached.hpp>
#include <exec/async_scope.hpp>

exec::task<void> co_main(asioice::net::io_context &ctx, std::size_t time) {
    using namespace asioice;
    using Socket =
        net::basic_datagram_socket<net::ip::udp,
                                   typename net::io_context::executor_type>;
    using Agent = basic_agent<Socket>;

    agent_config config1{.username = "agent1",
                         .password = "password1",
                         .ice_controlling = true,
                         .use_loopback = true};
    agent_config config2{.username = "agent2",
                         .password = "password2",
                         .ice_controlling = false,
                         .use_loopback = true};

    Agent ag1(ctx.get_executor(), config1);
    Agent ag2(ctx.get_executor(), config2);

    std::cout << "Gathering...\n";
    co_await stdexec::when_all(ag1.gather_candidates(),
                               ag2.gather_candidates());
    std::cout << "Stop gathering\n";

    for (const auto &c : ag1.local_candidates())
        co_await ag2.add_remote_candidate(c);
    co_await ag2.add_remote_candidate();
    ag2.set_remote_username("agent1");
    ag2.set_remote_password("password1");

    for (const auto &c : ag2.local_candidates())
        co_await ag1.add_remote_candidate(c);
    co_await ag1.add_remote_candidate();
    ag1.set_remote_username("agent2");
    ag1.set_remote_password("password2");

    std::cout << "Connecting...\n";
    std::tuple<std::tuple<bool>, std::tuple<bool>> connect_result =
        co_await stdexec::when_all(ag1.connect(), ag2.connect());
    if (std::get<0>(std::get<0>(connect_result)) &&
        std::get<0>(std::get<1>(connect_result)))
        std::cout << "Connected\n";
    else {
        std::cout << "Failed to connect\n";
        co_return;
    }

    exec::async_scope scope;
    std::size_t n = 0;

    // use one byte header to demultiplex with STUN
    std::string_view ping = "\4ping";
    std::string_view pong = "\4pong";
    async_queue<io_buffer_ptr> q1, q2;
    ag1.on_data([&](io_buffer_ptr &data, uint8_t component) {
        q1.push(std::move(data));
    });
    ag2.on_data([&](io_buffer_ptr &data, uint8_t component) {
        q2.push(std::move(data));
    });
    auto ag1_recv = [&]() -> asioice::task<void> {
        while (true) {
            std::optional<io_buffer_ptr> data =
                co_await q1.async_pop_stoppable();
            if (!data)
                co_return;
            std::string_view msg{(const char *)(*data)->data(),
                                 (*data)->size()};
            if (msg == pong) {
                ++n;
                co_await ag1.sendto(net::buffer(ping), 1);
            }
        }
    };
    auto ag2_recv = [&]() -> asioice::task<void> {
        while (true) {
            std::optional<io_buffer_ptr> data =
                co_await q2.async_pop_stoppable();
            if (!data)
                co_return;
            std::string_view msg{(const char *)(*data)->data(),
                                 (*data)->size()};
            if (msg == ping)
                co_await ag2.sendto(net::buffer(pong), 1);
        }
    };
    scope.spawn(ag1_recv());
    scope.spawn(ag2_recv());
    co_await ag1.sendto(net::buffer(ping), 1);

    net::steady_timer timer(ctx, std::chrono::seconds(time));
    co_await timer.async_wait(utils::use_sender);
    scope.request_stop();
    co_await scope.on_empty();

    std::cout << "PING_PONG " << n << " times in " << time << " seconds\n";
    std::cout << "closing...\n";
}

int main(int argc, char **argv) {
    asioice::net::io_context ctx(BOOST_ASIO_CONCURRENCY_HINT_UNSAFE); // single thread
    exec::start_detached(
        stdexec::starts_on(stdexec::inline_scheduler{},
                           co_main(ctx, argc > 1 ? std::atoi(argv[1]) : 10)));
    ctx.run();
}
