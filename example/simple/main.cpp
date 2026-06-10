#include "asioice.hpp"

#if ASIOICE_USE_BOOST_ASIO
#include <boost/asio/io_context.hpp>
#else
#include <asio/io_context.hpp>
#endif

#include <iostream>
#include <exec/start_detached.hpp>

asioice::task<void> co_main(asioice::net::io_context &ctx) {
    using namespace asioice;

    agent_config config1{.username = "agent1",
                         .password = "password1",
                         .ice_controlling = true,
                         .use_loopback = true};
    agent_config config2{.username = "agent2",
                         .password = "password2",
                         .ice_controlling = false,
                         .use_loopback = true};

    agent ag1(ctx.get_executor(), config1);
    agent ag2(ctx.get_executor(), config2);

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
    else
        std::cout << "Failed to connect\n";
    std::cout << "closing...\n";
}

int main() {
    asioice::net::io_context ctx;
    exec::start_detached(co_main(ctx));
    ctx.run();
}
