#include "asioice/agent.hpp"
#include "asioice/data_channel.hpp"
#include "asioice/detail/ignore.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/dtls_transport.hpp"
#include "asioice/sctp_transport.hpp"
#include "asioice/socket_transport.hpp"
#include "asioice/ssl/dtls_config.hpp"
#include "hash.hpp"
#include "json.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
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
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
using namespace asioice;
using ws_t = websocket::stream<beast::tcp_stream>;
using ws_ptr = std::shared_ptr<ws_t>;
static const uint16_t PORT = 8083;

static const char *k_html_page = R"html(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>asio-ice Browser WebRTC Demo</title>
<style>
body{font-family:monospace;max-width:700px;margin:40px auto;padding:0 20px;background:#111;color:#0f0}
button{padding:8px 16px;font:inherit;cursor:pointer}
#log{background:#000;border:1px solid #333;padding:10px;height:300px;overflow-y:auto;white-space:pre-wrap;margin:10px 0}
</style>
</head>
<body>
<h2>asio-ice Browser WebRTC Demo</h2>
<p>Server: <input id="wsu" value="ws://localhost:8083/ws" style="width:300px;font:inherit">
<button onclick="connect()">Connect</button></p>
<div id="log"></div>
<script>
const E=(id)=>document.getElementById(id);
function log(s){const l=E('log');l.textContent+=s+'\n';l.scrollTop=l.scrollHeight;}
async function connect(){
log('Connecting...');
const ws=new WebSocket(E('wsu').value);
const opened=new Promise(r=>{ws.onopen=()=>r();});
ws.onerror=()=>log('WebSocket error');
ws.onclose=()=>log('WebSocket closed');
const pc=new RTCPeerConnection({iceServers:[{urls:'stun:14.29.112.241:20002'}]});
pc.oniceconnectionstatechange=()=>log('ICE state: '+pc.iceConnectionState);
pc.onicegatheringstatechange=()=>log('ICE gathering: '+pc.iceGatheringState);
const dc=pc.createDataChannel('pingpong');
log('Created DataChannel: '+dc.label);
dc.onopen=()=>{log('DataChannel OPEN!');dc.send('ping');log('Sent: ping');setInterval(()=>{if(dc.readyState!=='open'){log('DC not open, state='+dc.readyState);return;}dc.send('ping');log('Sent: ping');},1000);};dc.onclose=()=>log('DataChannel CLOSED');dc.onerror=(e)=>log('DataChannel error: '+(e.error?e.error.message:'unknown'));
dc.onmessage=(e)=>{log('Recv: '+e.data);if(e.data==='pong')log('Ping-pong SUCCESS!');};
ws.onmessage=async(e)=>{log('WS recv: '+e.data);const m=JSON.parse(e.data);if(m.type==='answer'){log('Got answer');await pc.setRemoteDescription(new RTCSessionDescription({type:'answer',sdp:m.sdp}));log('Remote description set');}};
const offer=await pc.createOffer();
await pc.setLocalDescription(offer);
log('Local description set, gathering...');
await new Promise(r=>{if(pc.iceGatheringState==='complete')r();else pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState==='complete')r();};});
log('Candidates gathered');
await opened;
let s=pc.localDescription.sdp;
log('Offer SDP:\\n'+s);
ws.send(JSON.stringify({type:'offer',sdp:s}));
log('Offer sent');
await new Promise(r=>{const d=()=>{pc.oniceconnectionstatechange=null;r();};pc.oniceconnectionstatechange=()=>{const t=pc.iceConnectionState;log('ICE state: '+t);if(t==='connected'||t==='failed'||t==='disconnected')d();};ws.onclose=()=>{log('WebSocket closed');d();};});
}
</script>
</body>
</html>
)html";

static task<void> ws_send(ws_t &ws, const nlohmann::json &msg) {
    ws.text(true);
    auto d = msg.dump();
    auto [ec, n] = co_await ws.async_write(
        net::buffer(d), net::as_tuple(asio2exec::use_sender));
    if (ec)
        std::cerr << "ws err: " << ec.message() << '\n';
}

static task<nlohmann::json> ws_recv(ws_t &ws) {
    beast::flat_buffer buf;
    auto [ec, n] =
        co_await ws.async_read(buf, net::as_tuple(asio2exec::use_sender));
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
    asio2exec::scheduler sched{ctx};
    ssl::dtls_certificate cert;
    std::string local_fp = cert.get_fingerprint_sha256();
    std::cout << "DTLS fp: " << local_fp << '\n';

    auto offer = parse_sdp((co_await ws_recv(*ws))["sdp"].get<std::string>());
    std::cout << "Offer: ufrag=" << offer.ufrag << " fp=" << offer.fp
              << " cands=" << offer.cands.size() << '\n';

    for (const auto &c : offer.cands)
        std::cout << "Remote candidate: " << c << '\n';

    std::string local_user, local_pass;
    {
        char buf[32];
        asioice::hash::random_bytes(buf, sizeof(buf));
        auto hex = [](auto *p, size_t n) {
            std::ostringstream oss;
            oss << std::hex;
            for (size_t i = 0; i < n; ++i)
                oss << std::setw(2) << std::setfill('0')
                    << (unsigned)(unsigned char)p[i];
            return oss.str();
        };
        local_user = hex(buf, 8);  // 16 hex chars
        local_pass = hex(buf, 32); // 64 hex chars, ok per spec (22-256)
    }

    agent_config cfg = {
        .username = local_user,
        .password = local_pass,
        .ice_controlling = false,
        .use_loopback = true,
        .stun_servers = {{net::ip::make_address("14.29.112.241"), 20002}},
        .component_count = 1,
        .enable_mdns = true};
    cfg.trickle_ice = false;
    cfg.connectivity_check_timeout = std::chrono::milliseconds(30 * 1000);

    agent ag(ctx.get_executor(), cfg);
    ag.set_remote_username(offer.ufrag);
    ag.set_remote_password(offer.pwd);

    using IceT = agent::ice_transport_type;
    using DtlsT = ssl::dtls_transport<IceT>;
    using SctpT = sctp::transport<DtlsT>;
    using DcMgr = data_channel_manager<SctpT>;
    using Datachannel = typename DcMgr::data_channel;

    auto ice = ag.create_ice_transport(1);
    auto dtls = std::make_shared<DtlsT>(ice, std::move(cert));
    dtls->set_expected_remote_fingerprint(offer.fp);

    for (const auto &line : offer.cands) {
        auto c = candidate::from_sdp(line);
        if (c)
            co_await ag.add_remote_candidate(std::move(*c));
    }
    co_await ag.add_remote_candidate();

    net::steady_timer timer(ctx, std::chrono::seconds(5));
    co_await utils::stop_when(ag.gather_candidates(),
                              timer.async_wait(asio2exec::use_sender));

    for (const auto &p : ag.candidate_pairs()) {
        std::cout << "candidate pairs: " << p->to_string(2) << '\n';
    }

    std::ostringstream sdp;
    sdp << "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
        << "a=group:BUNDLE 0\r\n"
        << "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        << "c=IN IP4 0.0.0.0\r\na=mid:0\r\n"
        << "a=ice-ufrag:" << ag.local_username() << "\r\n"
        << "a=ice-pwd:" << ag.local_password() << "\r\n"
        << "a=fingerprint:sha-256 " << local_fp << "\r\n"
        << "a=setup:active\r\n"
        << "a=sctp-port:5000\r\n"
        << "a=max-message-size:65536\r\n";
    for (const auto &c : ag.local_candidates())
        sdp << "a=" << c.to_sdp() << "\r\n";
    co_await ws_send(*ws, {{"type", "answer"}, {"sdp", sdp.str()}});
    std::cout << "Sent answer, connecting:" << sdp.str() << '\n';

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
    std::cout << "DTLS OK, fp: " << dtls->get_remote_fingerprint_sha256()
              << '\n';

    auto sctp = std::make_shared<SctpT>(dtls, exsctp::sctp_options{});

    sctp->start();

    timer.expires_after(std::chrono::seconds(2));
    co_await timer.async_wait(asio2exec::use_sender);

    std::cout << "SCTP accept...\n";
    bool sctp_connected = co_await sctp->accept();
    if (!sctp_connected) {
        std::cerr << "SCTP accept failed\n";
        co_return;
    }
    std::cout << "SCTP connected!\n";

    exec::async_scope scope;
    DcMgr dc_mgr(sctp, true);

    dc_mgr.on_remote_channel([&scope](std::shared_ptr<Datachannel> ch) {
        std::cout << "Remote DataChannel: " << ch->label() << " (stream "
                  << ch->stream_id() << ")\n";
        scope.spawn([](std::shared_ptr<Datachannel> ch) -> task<void> {
            utils::scope_guard on_exit(
                []() noexcept { std::cout << "Channel closed\n"; });
            while (true) {
                data_channel_message msg = co_await ch->read();
                std::string_view text(
                    reinterpret_cast<const char *>(msg.data.data()),
                    msg.data.size());
                std::cout << "Recv on '" << ch->label() << "': " << text
                          << '\n';

                if (text == "ping") {
                    co_await ch->send_text("pong");
                    std::cout << "Sent pong\n";
                }
            }
        }(std::move(ch)));
    });

    dc_mgr.start();
    std::cout << "Waiting 30s for DataChannel ping-pong...\n";

    net::steady_timer wait_timer(ctx, std::chrono::seconds(30));
    co_await wait_timer.async_wait(asio2exec::use_sender);

    std::cout << "Shutting down...\n";
    dc_mgr.stop();
    co_await sctp->shutdown();
    ag.close();
    std::cout << "Session closed.\n";

    scope.request_stop();
    co_await (scope.on_empty() | stdexec::continues_on(sched));
}

static task<void> http_session(net::io_context &ctx,
                               net::ip::tcp::socket sock) {
    beast::flat_buffer buf;
    http::request<http::string_body> req;
    auto [ec, n] = co_await http::async_read(
        sock, buf, req, net::as_tuple(asio2exec::use_sender));
    if (ec)
        co_return;
    if (websocket::is_upgrade(req)) {
        auto ws = std::make_shared<ws_t>(std::move(sock));
        ws->set_option(websocket::stream_base::timeout::suggested(
            beast::role_type::server));
        auto [wec] = co_await ws->async_accept(
            req, net::as_tuple(asio2exec::use_sender));
        if (wec)
            co_return;
        co_await ice_dtls_sctp_session(ctx, ws);
        co_return;
    }
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "asio-ice");
    res.set(http::field::content_type, "text/html");
    res.body() = k_html_page;
    res.prepare_payload();
    co_await http::async_write(sock, res, net::as_tuple(asio2exec::use_sender));
}

static task<void> listener(net::io_context &ctx) {
    net::ip::tcp::acceptor acc(
        ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), PORT));
    std::cout << "Server on http://localhost:" << PORT << '\n';
    while (true) {
        auto [ec, sock] =
            co_await acc.async_accept(net::as_tuple(asio2exec::use_sender));
        if (ec)
            continue;
        exec::start_detached(http_session(ctx, std::move(sock)));
    }
}

int main() {
    std::cout << std::unitbuf;
    net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, listener(ctx)));
    ctx.run();
}
