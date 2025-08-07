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
#include "stop_when.hpp"
#include "scope_guard.hpp"

#include <exec/async_scope.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include "asio2exec.hpp"
#include <asio/io_context.hpp>
#include <asio/ip/host_name.hpp>
#include <asio/ip/basic_endpoint.hpp>
#include <asio/ip/udp.hpp>
#include <asio/as_tuple.hpp>
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
#include <ranges>

namespace ice::impl {

template <class Layer>
struct agent_datagram_impl
    : std::enable_shared_from_this<agent_datagram_impl<Layer>> {
    using endpoint_type = typename Layer::endpoint_type;
    using protocol_type = typename endpoint_type::protocol_type;
    using raw_transport = datagram_transport<Layer>;
    using raw_transport_ptr = std::shared_ptr<raw_transport>;

    agent_datagram_impl(net::io_context &ctx, agent_config config) noexcept
        : _ctx(ctx), _config(std::move(config)) {}

    agent_datagram_impl(const agent_datagram_impl &) = delete;
    agent_datagram_impl &operator=(const agent_datagram_impl &) = delete;
    agent_datagram_impl(agent_datagram_impl &&) = delete;
    agent_datagram_impl &operator=(agent_datagram_impl &&) = delete;

    ice::task<std::vector<ice::candidate>>
    get_component_candidates(auto &stun_client, uint8_t component,
                             const std::vector<net::ip::address> &addresses,
                             std::chrono::milliseconds timeout, auto... self);

    ice::task<void>
    server_reflexive_candidate(std::vector<ice::candidate> &srflx_candidates,
                               const ice::candidate &local_candidate,
                               auto &client, const endpoint_type &stun_server,
                               auto... self) noexcept;

    ice::task<void> server_reflexive_candidate(
        exec::async_scope &scope, std::vector<ice::candidate> &srflx_candidates,
        const std::vector<ice::candidate> &local_candidates, auto &client,
        const std::vector<std::string> &stun_servers, auto... self) noexcept;

    ice::task<void>
    resolve_server(net::ip::basic_resolver<protocol_type> &resolver,
                   std::string_view stun_server,
                   std::vector<endpoint_type> &endpoints);

  private:
    net::io_context &_ctx;
    agent_config _config;
};

} // namespace ice::impl

#include "impl/ice_impl.ipp"

inline void get_local_addresses_test(uint64_t n) {
    using namespace ice;
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

inline void gathering_test(uint64_t n) try {
    using namespace ice;
    net::io_context ctx;

    stun::client<datagram_transport<net::ip::udp::socket>, true> client(ctx);

    agent_config config;
    config.stun_servers = {"stun.l.google.com:19302", "14.29.112.241:20002"};

    std::vector<net::ip::address> local_addresses = get_local_addresses();

    auto agent =
        std::make_shared<impl::agent_datagram_impl<net::ip::udp::socket>>(
            ctx, config);

    auto work =
        agent->get_component_candidates(client, 0, local_addresses,
                                        std::chrono::milliseconds(5 * 1000)) |
        stdexec::then([](std::vector<candidate> candidates) {
            std::cout << "Candidates: " << candidates.size() << '\n';
            for (const auto &c : candidates)
                std::cout << c.to_string() << '\n';
        }) |
        stdexec::upon_stopped([] { std::cout << "Timeout\n"; });

    stdexec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, std::move(work)));

    ctx.run();
} catch (const std::exception &e) {
    std::cerr << "Unhandled exception: " << e.what() << '\n';
}

namespace ice {
void debug_test() {
    // get_local_addresses_test(1000);
    gathering_test(1);
}
} // namespace ice