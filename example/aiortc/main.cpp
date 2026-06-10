#include "asioice/agent.hpp"
#include "asioice/data_channel.hpp"
#include "asioice/detail/ignore.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/dtls_transport.hpp"
#include "asioice/sctp_transport.hpp"
#include "asioice/socket_transport.hpp"
#include "asioice/ssl/dtls_config.hpp"
#include "json.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
namespace asioice {
namespace net = boost::asio;
}
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
#else
#error "Requires Boost.Asio"
#endif

#include <exec/async_scope.hpp>
#include <exec/start_detached.hpp>
#include <stdexec/execution.hpp>
#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
using namespace asioice;
using ws_t = websocket::stream<beast::tcp_stream>;
using ws_ptr = std::shared_ptr<ws_t>;
static const uint16_t PORT = 8080;

static task<void> ws_send(ws_t &ws, const nlohmann::json &msg) {
    ws.text(true);
    auto d = msg.dump();
    auto [ec, n] = co_await ws.async_write(
        net::buffer(d), net::as_tuple(asioice::utils::use_sender));
    if (ec)
        std::cerr << "ws err: " << ec.message() << '\n';
}

static task<nlohmann::json> ws_recv(ws_t &ws) {
    beast::flat_buffer buf;
    auto [ec, n] =
        co_await ws.async_read(buf, net::as_tuple(asioice::utils::use_sender));
    if (ec)
        throw std::runtime_error("ws recv: " + ec.message());
    auto j = nlohmann::json::parse(beast::buffers_to_string(buf.data()));
    buf.clear();
    co_return j;
}

struct remote_sdp {
    std::string ufrag, pwd, fp, setup;
    std::vector<std::string> cands;
};

static remote_sdp parse_sdp(std::string_view s) {
    remote_sdp d;
    std::string_view r = s;
    while (!r.empty()) {
        auto p = r.find("\r\n");
        if (p == std::string_view::npos)
            p = r.find('\n');
        auto l = r.substr(0, p);
        r.remove_prefix(
            p == std::string_view::npos
                ? r.size()
                : p + (l.size() < r.size() && r[l.size()] == '\r' ? 2 : 1));
        if (l.starts_with("a=ice-ufrag:"))
            d.ufrag = l.substr(12);
        else if (l.starts_with("a=ice-pwd:"))
            d.pwd = l.substr(10);
        else if (l.starts_with("a=fingerprint:sha-256 "))
            d.fp = l.substr(22);
        else if (l.starts_with("a=setup:"))
            d.setup = l.substr(8);
        else if (l.starts_with("a=") && l.substr(2).starts_with("candidate:"))
            d.cands.emplace_back(l.substr(2));
    }
    return d;
}

static task<void> ice_dtls_sctp_session(net::io_context &ctx, ws_ptr ws) {
    std::cout << "WS connected\n";
    asioice::utils::scheduler sched{ctx};
    ssl::dtls_certificate cert;
    auto local_fp = cert.get_fingerprint(ssl::hash_algorithm::sha256);
    std::cout << "DTLS fp: " << local_fp.value << '\n';

    auto offer = parse_sdp((co_await ws_recv(*ws))["sdp"].get<std::string>());
    std::cout << "Offer: ufrag=" << offer.ufrag << " fp=" << offer.fp
              << " cands=" << offer.cands.size() << '\n';

    agent_config cfg = {.username = "asioice_dtls",
                        .password = "dtls_pwd",
                        .ice_controlling = false,
                        .use_loopback = true,
                        .component_count = 1};
    cfg.trickle_ice = false;

    agent ag(ctx.get_executor(), cfg);
    ag.set_remote_username(offer.ufrag);
    ag.set_remote_password(offer.pwd);

    // Create transport stack early (before connect), like ice_test.cpp.
    // This ensures dtls_impl is registered as a receiver before
    // free_candidates() removes stun_receivers.
    using IceT = agent::ice_transport_type;
    using DtlsT = ssl::dtls_transport<IceT>;
    using SctpT = sctp::transport<DtlsT>;
    using DcMgr = data_channel_manager<SctpT>;
    using Datachannel = typename DcMgr::data_channel;

    auto ice = ag.create_ice_transport(1);
    auto dtls = std::make_shared<DtlsT>(ice, std::move(cert));
    dtls->set_expected_remote_fingerprint(
        ssl::fingerprint{ssl::hash_algorithm::sha256, offer.fp});

    for (const auto &line : offer.cands) {
        auto c = candidate::from_sdp(line);
        if (c)
            co_await ag.add_remote_candidate(std::move(*c));
    }
    co_await ag.add_remote_candidate();

    net::steady_timer timer(ctx, std::chrono::seconds(5));
    co_await utils::stop_when(ag.gather_candidates(),
                              timer.async_wait(asioice::utils::use_sender));

    std::ostringstream sdp;
    sdp << "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
        << "a=group:BUNDLE 0\r\n"
        << "m=application 9 DTLS/SCTP 5000\r\n"
        << "c=IN IP4 0.0.0.0\r\na=mid:0\r\n"
        << "a=ice-ufrag:" << ag.local_username() << "\r\n"
        << "a=ice-pwd:" << ag.local_password() << "\r\n"
        << "a=" << local_fp.to_sdp() << "\r\n"
        << "a=setup:active\r\n"
        << "a=sctpmap:5000 webrtc-datachannel 65535\r\n";
    for (const auto &c : ag.local_candidates())
        sdp << "a=" << c.to_sdp() << "\r\n";
    co_await ws_send(*ws, {{"type", "answer"}, {"sdp", sdp.str()}});
    std::cout << "Sent answer, connecting\n";

    bool connected = co_await ag.connect();
    if (connected) {
        std::cout << "ICE connected!\n";
    } else {
        std::cerr << "ICE failed to connect\n";
        co_return;
    }

    std::cout << "DTLS handshake (client)...\n";
    auto hs_ec = co_await dtls->async_handshake(DtlsT::handshake_type::client);
    if (hs_ec) {
        std::cerr << "DTLS failed: " << hs_ec.message() << '\n';
        co_return;
    }
    auto remote_fp = dtls->get_remote_fingerprint(ssl::hash_algorithm::sha256);
    std::cout << "DTLS OK, fp: " << remote_fp.value << '\n';

    auto sctp = std::make_shared<SctpT>(dtls, exsctp::sctp_options{});
    sctp->start();

    std::cout << "SCTP accept...\n";
    bool sctp_connected = co_await sctp->accept();
    if (!sctp_connected) {
        std::cerr << "SCTP accept failed\n";
        co_return;
    }
    std::cout << "SCTP connected!\n";

    exec::async_scope scope;
    DcMgr dc_mgr(sctp, true);

    dc_mgr.on_remote_channel([&dc_mgr,
                              &scope](std::shared_ptr<Datachannel> ch) {
        std::cout << "Remote DataChannel: " << ch->label() << " (stream "
                  << ch->stream_id() << ")\n";
        scope.spawn([](std::shared_ptr<Datachannel> ch) -> asioice::task<void> {
            while (true) {
                if (!co_await ch->send_text("pong")) {
                    std::cerr << "Send failed\n";
                    co_return;
                }
                data_channel_message msg = co_await ch->read();
                if (!msg.binary)
                    std::cout << "channel \"" << ch->label() << "\" received: "
                              << std::string_view{(const char *)msg.data.data(),
                                                  msg.data.size()}
                              << '\n';
            }
        }(std::move(ch)));
    });

    dc_mgr.start();
    std::cout << "Waiting 30s for DataChannel ping-pong...\n";
    timer.expires_after(std::chrono::seconds(30));
    co_await timer.async_wait(asioice::utils::use_sender);

    scope.request_stop();
    co_await (scope.on_empty() | stdexec::continues_on(sched));
}

static task<void> http_session(net::io_context &ctx,
                               net::ip::tcp::socket sock) {
    beast::flat_buffer buf;
    http::request<http::string_body> req;
    auto [ec, n] = co_await http::async_read(
        sock, buf, req, net::as_tuple(asioice::utils::use_sender));
    if (ec)
        co_return;
    if (websocket::is_upgrade(req)) {
        auto ws = std::make_shared<ws_t>(std::move(sock));
        ws->set_option(websocket::stream_base::timeout::suggested(
            beast::role_type::server));
        auto [wec] = co_await ws->async_accept(
            req, net::as_tuple(asioice::utils::use_sender));
        if (wec) {
            std::cerr << "WebSocket handshake failed: " << wec.message()
                      << '\n';
            co_return;
        }
        std::cout << "WebSocket handshake OK\n";
        co_await ice_dtls_sctp_session(ctx, ws);
        co_return;
    }
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "asio-ice");
    res.set(http::field::content_type, "text/plain");
    res.body() = "OK";
    res.prepare_payload();
    co_await http::async_write(sock, res,
                               net::as_tuple(asioice::utils::use_sender));
}

static task<void> listener(net::io_context &ctx) {
    net::ip::tcp::acceptor acc(
        ctx, net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), PORT));
    std::cout << "Server on ws://localhost:" << PORT << "/ws\n";
    while (true) {
        auto [ec, sock] = co_await acc.async_accept(
            net::as_tuple(asioice::utils::use_sender));
        if (ec)
            continue;
        exec::start_detached(http_session(ctx, std::move(sock)));
    }
}

int main() {
    std::cout << std::unitbuf;
    net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(asioice::utils::scheduler{ctx}, listener(ctx)));
    ctx.run();
}
