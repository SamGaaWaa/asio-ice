#include "asioice/agent.hpp"
#include "asioice/detail/stop_when.hpp"

#include "json.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
namespace asioice {
namespace net = boost::asio;
}
namespace beast = boost::beast;
namespace websocket = beast::websocket;
#else
#error "This example requires Boost.Asio (Boost.Beast)"
#endif

#include <exec/start_detached.hpp>
#include <stdexec/execution.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace asioice;
using websocket_t = websocket::stream<net::ip::tcp::socket>;

static const char *DEFAULT_SERVER = "localhost";
static const char *DEFAULT_PORT = "18080";
static const char *DEFAULT_ROOM = "default";

static task<void> ws_send_json(websocket_t &ws,
                                const nlohmann::json &msg) {
    ws.text(true);
    auto data = msg.dump();
    auto [ec, n] =
        co_await ws.async_write(net::buffer(data),
                                net::as_tuple(asio2exec::use_sender));
    if (ec)
        throw std::runtime_error("ws write: " + ec.message());
}

static task<nlohmann::json> ws_recv_json(websocket_t &ws) {
    beast::flat_buffer buffer;
    auto [ec, n] =
        co_await ws.async_read(buffer,
                               net::as_tuple(asio2exec::use_sender));
    if (ec)
        throw std::runtime_error("ws read: " + ec.message());
    auto result = nlohmann::json::parse(
        beast::buffers_to_string(buffer.data()));
    buffer.clear();
    co_return result;
}

static std::string build_local_sdp(const agent &ag) {
    std::ostringstream sdp;
    sdp << "v=0\r\n"
        << "o=- 0 0 IN IP4 0.0.0.0\r\n"
        << "s=-\r\n"
        << "t=0 0\r\n"
        << "a=ice-ufrag:" << ag.local_username() << "\r\n"
        << "a=ice-pwd:" << ag.local_password() << "\r\n";
    for (const auto &c : ag.local_candidates())
        sdp << "a=" << c.to_sdp() << "\r\n";
    return sdp.str();
}

struct remote_sdp_data {
    std::string ufrag;
    std::string pwd;
    std::vector<std::string> candidate_lines;
};

static remote_sdp_data parse_remote_sdp(std::string_view sdp) {
    remote_sdp_data data;
    std::string_view remaining = sdp;
    while (!remaining.empty()) {
        auto pos = remaining.find("\r\n");
        if (pos == std::string_view::npos)
            pos = remaining.find('\n');
        auto line = remaining.substr(0, pos);
        remaining.remove_prefix(
            pos == std::string_view::npos ? remaining.size()
            : pos + (line.size() < remaining.size() &&
                             remaining[line.size()] == '\r'
                         ? 2 : 1));
        if (line.starts_with("a=ice-ufrag:"))
            data.ufrag = line.substr(12);
        else if (line.starts_with("a=ice-pwd:"))
            data.pwd = line.substr(10);
        else if (line.starts_with("a=") &&
                 line.substr(2).starts_with("candidate:"))
            data.candidate_lines.emplace_back(line.substr(2));
    }
    return data;
}

static task<void> apply_remote_sdp(agent &ag,
                                    const remote_sdp_data &data) {
    ag.set_remote_username(data.ufrag);
    ag.set_remote_password(data.pwd);
    for (const auto &line : data.candidate_lines) {
        auto c = candidate::from_sdp(line);
        if (c)
            co_await ag.add_remote_candidate(std::move(*c));
    }
    co_await ag.add_remote_candidate();
}

static task<void> run_peer(net::io_context &ctx, bool,
                           std::string server_host,
                           std::string server_port,
                           std::string room) {
    std::cout << std::unitbuf;
    asio2exec::scheduler sched{ctx};

    net::ip::tcp::resolver resolver(ctx);
    auto [resolve_ec, results] =
        co_await resolver.async_resolve(
            server_host, server_port,
            net::as_tuple(asio2exec::use_sender));
    if (resolve_ec)
        throw std::runtime_error("resolver: " + resolve_ec.message());

    websocket_t ws(ctx);
    auto [connect_ec, ep] =
        co_await net::async_connect(
            beast::get_lowest_layer(ws), results,
            net::as_tuple(asio2exec::use_sender));
    if (connect_ec)
        throw std::runtime_error("tcp connect: " + connect_ec.message());

    std::string path = "/" + room;
    auto [hs_ec] = co_await ws.async_handshake(
        server_host, path,
        net::as_tuple(asio2exec::use_sender));
    if (hs_ec)
        throw std::runtime_error("ws handshake: " + hs_ec.message());

    auto role_msg = co_await ws_recv_json(ws);
    std::string role = role_msg["role"].get<std::string>();
    bool is_offerer = (role == "offerer");
    std::cout << "Role: " << role << '\n';

    agent_config config{
        .username = is_offerer ? "asioice_offerer" : "asioice_answerer",
        .password = is_offerer ? "offerer_pwd" : "answerer_pwd",
        .ice_controlling = is_offerer,
        .use_loopback = true,
        .stun_servers = {{net::ip::make_address("14.29.112.241"), 20002}},
        .component_count = 1,
        .trickle_ice = false};
    agent ag(ctx.get_executor(), config);

    std::cout << "Gathering candidates...\n";
    net::steady_timer gather_timer(ctx, std::chrono::seconds(5));
    co_await utils::stop_when(ag.gather_candidates(),
                               gather_timer.async_wait(
                                   asio2exec::use_sender));

    std::cout << "Local candidates (" << ag.local_candidates().size()
              << "):\n";
    for (const auto &c : ag.local_candidates())
        std::cout << "  " << c.to_sdp() << '\n';

    std::string local_sdp = build_local_sdp(ag);
    nlohmann::json sdp_msg{{"type", "sdp"}, {"sdp", local_sdp}};

    std::cout << (is_offerer ? "Sending SDP offer\n"
                             : "Received SDP offer, sending answer\n");

    if (is_offerer) {
        co_await ws_send_json(ws, sdp_msg);
        auto resp = co_await ws_recv_json(ws);
        co_await apply_remote_sdp(
            ag, parse_remote_sdp(resp["sdp"].get<std::string>()));
    } else {
        auto resp = co_await ws_recv_json(ws);
        co_await apply_remote_sdp(
            ag, parse_remote_sdp(resp["sdp"].get<std::string>()));
        co_await ws_send_json(ws, sdp_msg);
    }

    std::cout << "Connecting (30s timeout)...\n";
    net::steady_timer connect_timer(ctx, std::chrono::seconds(30));
    co_await utils::stop_when(ag.connect(),
                               connect_timer.async_wait(
                                   asio2exec::use_sender));

    if (ag.state() != agent_state_t::CONNECTED) {
        std::cerr << "ICE failed: state=" << (int)ag.state() << '\n';
        co_return;
    }
    std::cout << "ICE connected!\n";

    int recv_count = 0;
    ag.on_data([&recv_count](io_buffer_ptr data, uint8_t) {
        ++recv_count;
        const char *p = (const char *)data->data();
        std::size_t n = data->size();
        if (n > 1 && (uint8_t)p[0] == 0x10)
            std::cout << "[" << recv_count << "] "
                      << std::string_view{p + 1, n - 1} << '\n';
    });

    // send a message every 1 second
    std::string payload =
        (is_offerer ? "C++ offerer#" : "C++ answerer#") +
        std::to_string(0);
    for (int i = 1; i <= 30; ++i) {
        net::steady_timer timer(ctx, std::chrono::seconds(1));
        co_await timer.async_wait(asio2exec::use_sender);

        if (ag.state() != agent_state_t::CONNECTED)
            break;

        payload.back() = '0' + (char)(i % 10);
        auto [send_ec, n] =
            co_await ag.sendto(net::buffer(payload), 1);
        if (!send_ec)
            std::cout << "Sent: " << payload << '\n';
        else {
            std::cerr << "Send error: " << send_ec.message() << '\n';
            break;
        }
    }

    ag.close();
}

int main(int argc, char *argv[]) {
    std::string server = DEFAULT_SERVER;
    std::string port = DEFAULT_PORT;
    std::string room = DEFAULT_ROOM;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--server" && i + 1 < argc)
            server = argv[++i];
        else if (arg == "--port" && i + 1 < argc)
            port = argv[++i];
        else if (arg == "--room" && i + 1 < argc)
            room = argv[++i];
    }

    try {
        net::io_context ctx;
        exec::start_detached(stdexec::starts_on(
            asio2exec::scheduler{ctx},
            run_peer(ctx, true, server, port, room)));
        ctx.run();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
