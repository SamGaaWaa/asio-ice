#include "asioice/agent.hpp"
#include "asioice/detail/ignore.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/dtls_transport.hpp"
#include "asioice/socket_transport.hpp"
#include "asioice/ssl/dtls_config.hpp"
#include "json.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/args.hpp>
namespace asioice {
namespace net = boost::asio;
}
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace bp = boost::process::v1;
#else
#error "Requires Boost.Asio"
#endif

#include <exec/async_scope.hpp>
#include <exec/start_detached.hpp>
#include <stdexec/execution.hpp>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>
using namespace asioice;
using ws_t = websocket::stream<beast::tcp_stream>;
using ws_ptr = std::shared_ptr<ws_t>;
static const uint16_t PORT = 8080;

static task<void> ws_send(ws_t &ws, const nlohmann::json &msg) {
    ws.text(true);
    auto d = msg.dump();
    auto [ec, n] = co_await ws.async_write(net::buffer(d),
                                           net::as_tuple(utils::use_sender));
    if (ec)
        std::cerr << "ws err: " << ec.message() << '\n';
}

static task<nlohmann::json> ws_recv(ws_t &ws) {
    beast::flat_buffer buf;
    auto [ec, n] =
        co_await ws.async_read(buf, net::as_tuple(utils::use_sender));
    if (ec)
        throw std::runtime_error("ws recv: " + ec.message());
    auto j = nlohmann::json::parse(beast::buffers_to_string(buf.data()));
    buf.clear();
    co_return j;
}

struct remote_sdp {
    std::string ufrag, pwd, fp, setup;
    std::vector<std::string> cands;
    std::vector<std::string> media_payloads;
};

static remote_sdp parse_sdp(std::string_view s) {
    remote_sdp d;
    std::string_view r = s;
    bool in_video = false;
    while (!r.empty()) {
        auto p = r.find("\r\n");
        if (p == std::string_view::npos)
            p = r.find('\n');
        auto l = r.substr(0, p);
        r.remove_prefix(
            p == std::string_view::npos
                ? r.size()
                : p + (l.size() < r.size() && r[l.size()] == '\r' ? 2 : 1));
        if (l.starts_with("m=video"))
            in_video = true;
        else if (!l.empty() && l[0] != 'a' && l[0] != 'm')
            in_video = false;
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
static std::string
srtp_suite_name(ssl::srtp_protection_profile profile) {
    switch (profile) {
    case ssl::srtp_protection_profile::srtp_aes128_cm_sha1_80:
        return "AES_CM_128_HMAC_SHA1_80";
    case ssl::srtp_protection_profile::srtp_aes128_cm_sha1_32:
        return "AES_CM_128_HMAC_SHA1_32";
    case ssl::srtp_protection_profile::srtp_aead_aes_128_gcm:
        return "AES_128_GCM";
    case ssl::srtp_protection_profile::srtp_aead_aes_256_gcm:
        return "AES_256_GCM";
    default:
        return "";
    }
}

static std::string
format_srtp_params(const ssl::srtp_key_material &keys) {
    std::vector<uint8_t> material;
    material.insert(material.end(), keys.client_write_key.begin(),
                    keys.client_write_key.end());
    material.insert(material.end(), keys.client_write_salt.begin(),
                    keys.client_write_salt.end());
    auto n = beast::detail::base64::encoded_size(material.size());
    std::string out(n, '\0');
    beast::detail::base64::encode(out.data(), material.data(),
                                  material.size());
    return out;
}

static std::string find_in_path(const std::string &name) {
    const char *path = std::getenv("PATH");
    if (!path)
        return name;
    std::string_view pv(path);
    while (!pv.empty()) {
        auto colon = pv.find(':');
        auto dir = pv.substr(0, colon);
        if (colon == std::string_view::npos)
            pv = {};
        else
            pv.remove_prefix(colon + 1);
        auto full = std::string(dir) + "/" + name;
        if (::access(full.c_str(), X_OK) == 0)
            return full;
    }
    return name;
}

static task<void> ffmpeg_session(net::io_context &ctx, ws_ptr ws) {
    std::cout << "WS connected (ffmpeg SRTP demo)\n";
    utils::scheduler sched{ctx};
    ssl::dtls_certificate cert;
    auto local_fp = cert.get_fingerprint(ssl::hash_algorithm::sha256);
    std::cout << "DTLS fp: " << local_fp.value << '\n';

    auto offer = parse_sdp((co_await ws_recv(*ws))["sdp"].get<std::string>());
    std::cout << "Offer: ufrag=" << offer.ufrag << " fp=" << offer.fp
              << " cands=" << offer.cands.size() << '\n';

    agent_config cfg = {.username = "asioice_ffmpeg",
                        .password = "ffmpeg_pwd",
                        .ice_controlling = false,
                        .use_loopback = true,
                        .component_count = 1};
    cfg.trickle_ice = false;

    agent ag(ctx.get_executor(), cfg);
    ag.set_remote_username(offer.ufrag);
    ag.set_remote_password(offer.pwd);

    using IceT = agent::ice_transport_type;
    using DtlsT = ssl::dtls_transport<IceT>;

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
                              timer.async_wait(utils::use_sender));

    std::ostringstream sdp;
    sdp << "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
        << "a=group:BUNDLE 0\r\n"
        << "m=video 9 UDP/TLS/RTP/SAVPF 97\r\n"
        << "c=IN IP4 0.0.0.0\r\na=mid:0\r\n"
        << "a=sendonly\r\n"
        << "a=rtcp-mux\r\n"
        << "a=rtpmap:97 VP8/90000\r\n"
        << "a=ssrc:1 cname:asioice-ffmpeg\r\n"
        << "a=ice-ufrag:" << ag.local_username() << "\r\n"
        << "a=ice-pwd:" << ag.local_password() << "\r\n"
        << "a=fingerprint:" << local_fp.to_sdp() << "\r\n"
        << "a=setup:active\r\n";
    for (const auto &c : ag.local_candidates())
        sdp << "a=" << c.to_sdp() << "\r\n";
    co_await ws_send(*ws, {{"type", "answer"}, {"sdp", sdp.str()}});
    std::cout << "Sent answer, connecting\n";

    bool connected = co_await ag.connect();
    if (!connected) {
        std::cerr << "ICE failed to connect\n";
        co_return;
    }
    std::cout << "ICE connected!\n";

    std::cout << "DTLS handshake (client)...\n";
    auto hs_ec = co_await dtls->async_handshake(DtlsT::handshake_type::client);
    if (hs_ec) {
        std::cerr << "DTLS failed: " << hs_ec.message() << '\n';
        co_return;
    }
    auto remote_fp = dtls->get_remote_fingerprint(ssl::hash_algorithm::sha256);
    std::cout << "DTLS OK, remote fp: " << remote_fp.value << '\n';

    auto keys = dtls->export_srtp_key_material();
    if (!keys || keys->profile == ssl::srtp_protection_profile::none) {
        std::cerr << "No SRTP key material exported\n";
        co_return;
    }
    std::cout << "SRTP profile: " << srtp_suite_name(keys->profile) << '\n'
              << "  client_write_key: " << keys->client_write_key.size()
              << "B\n"
              << "  client_write_salt: " << keys->client_write_salt.size()
              << "B\n"
              << "  server_write_key: " << keys->server_write_key.size()
              << "B\n"
              << "  server_write_salt: " << keys->server_write_salt.size()
              << "B\n";

    net::ip::udp::socket relay(ctx);
    relay.open(net::ip::udp::v4());
    relay.bind(net::ip::udp::endpoint(net::ip::address_v4::loopback(), 0));
    auto relay_ep = relay.local_endpoint();
    std::cout << "Relay UDP socket: " << relay_ep << '\n';

    auto params = format_srtp_params(*keys);
    auto suite = srtp_suite_name(keys->profile);
    std::ostringstream srtp_url;
    srtp_url << "srtp://127.0.0.1:" << relay_ep.port() << "?pkt_size=1316"
             << "&srtp_out_suite=" << suite << "&srtp_out_params=" << params;

    std::cout << "Launching ffmpeg...\n";
    bp::child ffmpeg_proc;
    try {
        auto ffmpeg_path = find_in_path("ffmpeg");
        std::vector<std::string> ff_args = {
            "-re", "-f", "lavfi",
            "-i",
            "testsrc2=duration=30:size=640x480:rate=30",
            "-c:v", "libvpx", "-cpu-used", "5",
            "-deadline", "realtime", "-b:v", "1M",
            "-payload_type", "97",
            "-f", "rtp", srtp_url.str()};
        ffmpeg_proc =
            bp::child(ffmpeg_path, bp::args = ff_args);
    } catch (const std::exception &e) {
        std::cerr << "Failed to launch ffmpeg: " << e.what()
                  << "\n";
        co_return;
    }
    if (!ffmpeg_proc.running()) {
        std::cerr << "ffmpeg failed to start\n";
        co_return;
    }
    std::cout << "ffmpeg pid=" << ffmpeg_proc.id() << '\n';
    exec::async_scope scope;
    scope.spawn([&](net::io_context &ctx, agent &ag,
                    net::ip::udp::socket &relay) -> task<void> {
        std::array<uint8_t, 1500> buf;
        int count = 0;
        while (true) {
            net::ip::udp::endpoint sender;
            auto [ec, n] = co_await relay.async_receive_from(
                net::buffer(buf), sender, net::as_tuple(utils::use_sender));
            if (ec) {
                if (ec != net::error::operation_aborted)
                    std::cerr << "Relay recv error: " << ec.message() << '\n';
                break;
            }
            auto [sec, sn] =
                co_await ag.sendto(net::buffer(buf, n), 1);
            if (sec) {
                std::cerr << "ICE sendto error: " << sec.message() << '\n';
                break;
            }
            count++;
        }
        std::cout << "Relay forwarded " << count << " packets\n";
    }(ctx, ag, relay));

    std::cout << "Relaying SRTP to peer, ctrl-c to stop\n";
    timer.expires_after(std::chrono::seconds(35));
    co_await timer.async_wait(utils::use_sender);

    scope.request_stop();
    relay.close();
    ffmpeg_proc.terminate();
    ffmpeg_proc.wait();
    co_await (scope.on_empty() | stdexec::continues_on(sched));
    std::cout << "Done\n";
}

static task<void> http_session(net::io_context &ctx,
                               net::ip::tcp::socket sock) {
    beast::flat_buffer buf;
    http::request<http::string_body> req;
    auto [ec, n] = co_await http::async_read(sock, buf, req,
                                             net::as_tuple(utils::use_sender));
    if (ec)
        co_return;
    if (websocket::is_upgrade(req)) {
        auto ws = std::make_shared<ws_t>(std::move(sock));
        ws->set_option(websocket::stream_base::timeout::suggested(
            beast::role_type::server));
        auto [wec] =
            co_await ws->async_accept(req, net::as_tuple(utils::use_sender));
        if (wec) {
            std::cerr << "WS handshake failed: " << wec.message() << '\n';
            co_return;
        }
        co_await ffmpeg_session(ctx, ws);
        co_return;
    }
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "asio-ice");
    res.set(http::field::content_type, "text/plain");
    res.body() = "OK";
    res.prepare_payload();
    co_await http::async_write(sock, res, net::as_tuple(utils::use_sender));
}

static task<void> listener(net::io_context &ctx) {
    net::ip::tcp::acceptor acc(
        ctx, net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), PORT));
    std::cout << "Server on ws://localhost:" << PORT << "/ws\n";
    while (true) {
        auto [ec, sock] =
            co_await acc.async_accept(net::as_tuple(utils::use_sender));
        if (ec)
            continue;
        exec::start_detached(http_session(ctx, std::move(sock)));
    }
}

int main() {
    std::cout << std::unitbuf;
    net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(utils::scheduler{ctx}, listener(ctx)));
    ctx.run();
}
