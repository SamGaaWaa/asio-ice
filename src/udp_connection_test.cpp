#include "config.hpp"
#include "task.hpp"
#include "scope_guard.hpp"
#include "udp_connection.hpp"

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
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
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <system_error>
namespace ice {
namespace net = asio;
using std::error_code;
} // namespace ice
#endif

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <iostream>

using namespace ice;
using namespace asio2exec;

void udp_connection_test() {
    net::io_context ctx;
    asio2exec::scheduler sched{ctx};

    net::ip::udp::endpoint local_ep(net::ip::address::from_string("127.0.0.1"),
                                    8013),
        remote1_ep(net::ip::address::from_string("127.0.0.1"), 8014),
        remote2_ep(net::ip::address::from_string("127.0.0.1"), 8015);

    std::shared_ptr<udp_proxy> proxy =
        std::make_shared<udp_proxy>(ctx, local_ep, net::ip::udp::v4());
    std::shared_ptr<udp_connection> client1 = proxy->connect(remote1_ep);
    std::shared_ptr<udp_connection> client2 = proxy->connect(remote2_ep);

    net::ip::udp::socket sender1{ctx, net::ip::udp::v4()},
        sender2{ctx, net::ip::udp::v4()};

    sender1.bind(remote1_ep);
    sender2.bind(remote2_ep);

    sender1.connect(local_ep);
    sender2.connect(local_ep);

    // using coro_task = ice::task<void>;
    using coro_task =
        exec::__task::basic_task<void, exec::__task::__raw_task_context<void>>;
    // using coro_task = exec::task<void>;

    auto client_coro = [&](udp_connection &client,
                           net::ip::udp::endpoint connected_ep) -> coro_task {
        std::size_t num = 0;

        ice::utils::scope_guard on_exit([&]() noexcept {
            std::cout << "totally received " << num << " bytes from "
                      << connected_ep.address().to_string() << ':'
                      << connected_ep.port() << '\n';
        });

        while (true) {
            auto pkg = co_await client.async_read();
            if (!pkg) {
                std::cerr << "Connection closed.\n";
                co_return;
            }
            // if (remote != connected_ep) {
            //     std::cout << "Should only receive from " <<
            //     connected_ep.address().to_string() << ':' <<
            //     connected_ep.port()
            //         << ", buf actually from " << remote.address().to_string()
            //         <<
            //         ':' << remote.port() << '\n';
            //     co_return;
            // }
            num += pkg->size();
            proxy->packet_cache().push_back(std::move(*pkg));
        }
    };

    auto printer = [](std::string_view str) {
        // static int times = 100;
        // if (times == 0)
        //     std::terminate();
        // std::cout << str << '\n';
        //--times;
    };

    auto sender_coro = [&](net::ip::udp::socket &sender) -> coro_task {
        std::string msg(1024, 'c');
        while (true) {
            auto [ec, n] = co_await sender.async_send(
                net::buffer(msg.data(), msg.size()), use_sender);
            if (ec)
                throw std::system_error{ec};
            // printer(std::to_string(sender.local_endpoint().port()));
            co_await stdexec::schedule(sched);
        }
    };

    auto timeout = [&](net::steady_timer &timer) -> coro_task {
        co_await timer.async_wait(use_sender);
        proxy->stop();
        co_await stdexec::just_stopped();
    };

    net::steady_timer timer{ctx};
    timer.expires_after(std::chrono::seconds(60));

    // proxy->set_filter([](const auto& ep, ice::packet& pkg) {
    //     return true;
    // });
    proxy->start();

    // stdexec::start_detached(
    //     stdexec::starts_on(
    //         sched,
    //         stdexec::when_all(
    //             client_coro(client1, remote1_ep),
    //             client_coro(client2, remote2_ep),
    //             sender_coro(sender1),
    //             sender_coro(sender2),
    //             stdexec::starts_on(sched, timer.async_wait(use_sender))
    //         )
    //     )
    //);

    stdexec::start_detached(stdexec::starts_on(
        sched,
        stdexec::when_all(timeout(timer), client_coro(*client1, remote1_ep),
                          client_coro(*client2, remote2_ep),
                          sender_coro(sender1), sender_coro(sender2))));

    ctx.run();
}

int main() { udp_connection_test(); }