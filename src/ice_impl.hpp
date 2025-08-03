#pragma once

#include "agent_config.hpp"
#include "ice.hpp"
#include "address.hpp"
#include "candidate.hpp"
#include "config.hpp"
#include "scope_guard.hpp"
#include "stun.hpp"
#include "stun_client.hpp"
#include "task.hpp"
#include "socket_transport.hpp"

#include <exec/async_scope.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
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
#include <memory>
#include <algorithm>

namespace ice {

template <class Layer>
struct datagram_impl: std::enable_shared_from_this<datagram_impl<Layer>> {
    using endpoint_type = typename Layer::endpoint_type;
    using raw_transport = typename datagram_transport<Layer>;
    using raw_transport_ptr = std::shared_ptr<raw_transport>;

    datagram_impl(net::io_context &ctx, agent_config config) noexcept:
        _ctx(ctx),
        _config(std::move(config)),
    {}

    datagram_impl(const datagram_impl &) = delete;
    datagram_impl &operator=(const datagram_impl &) = delete;
    datagram_impl(datagram_impl &&) = delete;
    datagram_impl &operator=(datagram_impl &&) = delete;

    ice::task<std::vector<std::pair<raw_transport_ptr, ice::candidate>>>
    get_component_candidates(
        uint8_t component,
        const std::vector<net::ip::address>& addresses,
        std::chrono::milliseconds timeout);

private:
    net::io_context &_ctx;
    agent_config _config;
    std::vector<raw_transport_ptr> _sockets;
};

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

#include "impl/ice_impl.ipp"