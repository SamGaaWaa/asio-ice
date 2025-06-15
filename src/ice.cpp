#include "ice.hpp"
#include "address.hpp"
#include "candidate.hpp"
#include "config.hpp"
#include "scope_guard.hpp"
#include "stun.hpp"
#include "stun_client.hpp"
#include "task.hpp"

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include "asio2exec.hpp"
#include <asio/io_context.hpp>
#include <asio/ip/host_name.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include <chrono>
#include <iostream>
#include <optional>
#include <vector>

namespace ice {

const char *version() { return "0.1.0"; }

template <class Endpoint, class Duration = std::chrono::milliseconds>
static ice::task<std::optional<endpoint>>
server_reflexive_endpoint(auto &client, Endpoint stun_server,
                          Duration timeout) noexcept try {
    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_BINDING;
    req.fill_random_transaction_id();

    stun::message resp;
    Endpoint from;
    auto result = co_await (client.request(stun_server, req, from, resp, 7) |
                            stdexec::stopped_as_optional());
    if (!result)
        co_return std::nullopt;
    if (from != stun_server) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_candidate: from != stun_server\n";
        }
        co_return std::nullopt;
    }
    ice::endpoint ep;
    if (resp.xor_mapped_address)
        ep = *resp.xor_mapped_address;
    else if (resp.mapped_address)
        ep = *resp.mapped_address;
    else
        co_return std::nullopt;
    co_return ep;
} catch (std::exception &e) {
    ICE_IN_DEBUG {
        std::cerr << "server_reflexive_candidate: " << e.what() << "\n";
    }
    co_return std::nullopt;
}

static void get_local_addresses_test(uint64_t n) {
    int addrs_num = 0;
    auto begin = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < n; ++i) {
        addrs_num += get_local_addresses().size();
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Result: " << (addrs_num / n) << '\n'
              << "Takes: "
              << (std::chrono::duration_cast<std::chrono::nanoseconds>(end -
                                                                       begin)
                      .count() /
                  n)
              << "ns\n";
}

static void server_reflexive_endpoint_test(uint64_t n) try {
    // net::io_context ctx;

    // net::ip::udp::resolver resolver(ctx);
    // auto resolve_result = resolver.resolve("14.29.112.241", "20002");
    // if (resolve_result.empty()) {
    //     std::cerr << "Resolve error\n";
    //     return;
    // }
    // const auto &server_ep = resolve_result->endpoint();
    // std::cout << "STUN server: " << server_ep.address().to_string() << ':'
    //           << server_ep.port() << '\n';

    // net::ip::udp::socket sock(ctx, net::ip::udp::v4());
    // sock.bind(net::ip::udp::endpoint(net::ip::udp::v4(), 0));
    // stun::client<net::ip::udp::socket> client(ctx, sock);

    // auto recv_coro = [&]() -> ice::task<void> {
    //     char buf[2048];
    //     while (true) {
    //         net::ip::udp::endpoint ep;
    //         auto [err, n] = co_await sock.async_receive_from(
    //             net::buffer(buf, sizeof(buf)), ep, asio2exec::use_sender);
    //         if (err) {
    //             std::cerr << "Receive error: " << err.message() << '\n';
    //             co_return;
    //         }
    //         std::cout << "Received " << n << " bytes from "
    //                   << ep.address().to_string() << ':' << ep.port() <<
    //                   '\n';
    //         if (!client.dispatch(ep, buf, n)) {
    //             std::cerr << "Dispatch error\n";
    //             co_return;
    //         }
    //     }
    // };

    // asio2exec::scheduler sched{ctx};
    // auto work = stdexec::when_all(
    //     recv_coro(),
    //     server_reflexive_endpoint(client, server_ep,
    //     std::chrono::seconds(10)) |
    //         stdexec::let_value([](std::optional<endpoint> &res) {
    //             if (!res) {
    //                 std::cerr << "Server reflexive endpoint not found\n";
    //             } else {
    //                 std::cout << "Server reflexive endpoint: "
    //                           << res->address.to_string() << ':' << res->port
    //                           << '\n';
    //             }
    //             return stdexec::just_stopped();
    //         }));
    // stdexec::start_detached(stdexec::starts_on(sched, std::move(work)));
    // ctx.run();
} catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << '\n';
}

void debug_test() {
    // get_local_addresses_test(1000);
    server_reflexive_endpoint_test(1000);
}

} // namespace ice