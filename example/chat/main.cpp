#include "asioice/agent.hpp"
#include "asioice/data_channel.hpp"
#include "asioice/detail/ignore.hpp"
#include "asioice/detail/on_scope_empty.hpp"
#include "asioice/detail/scope_guard.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/dtls_transport.hpp"
#include "asioice/sctp_transport.hpp"
#include "asioice/socket_transport.hpp"

#include <exec/async_scope.hpp>
#include <exec/start_detached.hpp>
#include <stdexec/execution.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include "asio2exec.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/steady_timer.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#error "Requires Boost.Asio"
#endif

#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
using namespace asioice;

static const char *GREEN = "\033[32m";
static const char *WHITE = "\033[37m";
static const char *RESET = "\033[0m";

static std::string enc(const std::string &s) {
    std::string r;
    r.reserve(s.size());
    for (char c : s) {
        if (c == '\r')
            r += "\\r";
        else if (c == '\n')
            r += "\\n";
        else if (c == '\\')
            r += "\\\\";
        else
            r += c;
    }
    return r;
}

static std::string dec(std::string_view s) {
    std::string r;
    r.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            if (s[i + 1] == 'r') {
                r += '\r';
                ++i;
            } else if (s[i + 1] == 'n') {
                r += '\n';
                ++i;
            } else if (s[i + 1] == '\\') {
                r += '\\';
                ++i;
            } else {
                r += s[i];
            }
        } else {
            r += s[i];
        }
    }
    return r;
}

static std::string random_username() {
    static const char *adjs[] = {
        "blue", "red",  "green", "silver", "gold",  "dark",  "light", "wild",
        "calm", "bold", "quick", "sharp",  "happy", "lucky", "sunny", "cool"};
    static const char *nouns[] = {"cat",  "dog",  "fox",  "owl",
                                  "bear", "hawk", "wolf", "deer",
                                  "fish", "bird", "lion", "tiger"};
    thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> adj_dist(0, 15);
    std::uniform_int_distribution<int> noun_dist(0, 11);
    std::uniform_int_distribution<int> num_dist(10, 99);
    return std::string(adjs[adj_dist(rng)]) + "_" + nouns[noun_dist(rng)] +
           std::to_string(num_dist(rng));
}

static task<std::optional<std::string>>
read_line(net::posix::stream_descriptor &stream, std::string &buffer) {
    while (buffer.find('\n') == std::string::npos) {
        char buf[256];
        auto [ec, n] = co_await stream.async_read_some(
            net::buffer(buf), net::as_tuple(asio2exec::use_sender));
        if (ec) {
            if (ec == net::error::eof)
                break;
            co_return std::nullopt;
        }
        buffer.append(buf, n);
    }
    auto pos = buffer.find('\n');
    std::string line;
    if (pos != std::string::npos) {
        line = buffer.substr(0, pos);
        buffer.erase(0, pos + 1);
    } else if (!buffer.empty()) {
        line = std::move(buffer);
        buffer.clear();
    } else {
        co_return std::nullopt; // EOF with empty buffer
    }
    while (!line.empty() && line.back() == '\r')
        line.pop_back();
    co_return line;
}

static task<std::string> prompt(net::posix::stream_descriptor &stdin_stream,
                                std::string &buf, std::string_view msg) {
    std::cout << msg << std::flush;
    auto r = co_await read_line(stdin_stream, buf);
    co_return r.value_or("");
}

static task<std::string> read_sdp(net::posix::stream_descriptor &stdin_stream,
                                  std::string &buf) {
    std::cout << "\nPaste SDP here (empty line to finish):\n";
    std::ostringstream oss;
    bool got_line = false;
    while (true) {
        auto opt = co_await read_line(stdin_stream, buf);
        if (!opt.has_value())
            break;
        std::string line = std::move(*opt);
        if (line.empty()) {
            if (!got_line)
                continue;
            break;
        }
        got_line = true;
        oss << line << "\r\n";
    }
    co_return oss.str();
}

struct remote_sdp {
    std::string ufrag, pwd, fp, setup, username;
    std::vector<std::string> cands;
};

static remote_sdp parse_sdp(std::string_view s) {
    remote_sdp d;
    while (!s.empty()) {
        auto p = s.find("\r\n");
        if (p == std::string_view::npos)
            p = s.find('\n');
        auto l = s.substr(0, p);
        s.remove_prefix(
            p == std::string_view::npos
                ? s.size()
                : p + (l.size() < s.size() && s[l.size()] == '\r' ? 2 : 1));
        if (l.starts_with("a=ice-ufrag:"))
            d.ufrag = l.substr(12);
        else if (l.starts_with("a=ice-pwd:"))
            d.pwd = l.substr(10);
        else if (l.starts_with("a=fingerprint:sha-256 "))
            d.fp = l.substr(22);
        else if (l.starts_with("a=setup:"))
            d.setup = l.substr(8);
        else if (l.starts_with("a=username:"))
            d.username = l.substr(11);
        else if (l.starts_with("a=") && l.substr(2).starts_with("candidate:"))
            d.cands.emplace_back(l.substr(2));
    }
    return d;
}

static std::string make_sdp(const agent &ag, const std::string &local_fp,
                            const std::string &setup,
                            const std::string &username) {
    std::ostringstream sdp;
    sdp << "v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
        << "a=group:BUNDLE 0\r\n"
        << "m=application 9 DTLS/SCTP 5000\r\n"
        << "c=IN IP4 0.0.0.0\r\na=mid:0\r\n"
        << "a=ice-ufrag:" << ag.local_username() << "\r\n"
        << "a=ice-pwd:" << ag.local_password() << "\r\n"
        << "a=fingerprint:sha-256 " << local_fp << "\r\n"
        << "a=setup:" << setup << "\r\n"
        << "a=sctpmap:5000 webrtc-datachannel 65535\r\n"
        << "a=username:" << username << "\r\n";
    for (const auto &c : ag.local_candidates())
        sdp << "a=" << c.to_sdp() << "\r\n";
    return sdp.str();
}

static task<void> chat_session(net::io_context &ctx) {
    asio2exec::scheduler sched{ctx};
    net::posix::stream_descriptor stdin_stream(ctx.get_executor(),
                                               STDIN_FILENO);
    std::string stdin_buf;

    std::string role_str = co_await prompt(stdin_stream, stdin_buf,
                                           "Which role? [o]ffer / [a]nswer: ");
    const bool is_offer =
        role_str == "o" || role_str == "O" || role_str == "offer";

    std::string username = co_await prompt(
        stdin_stream, stdin_buf, "Your username (enter for random): ");
    if (username.empty())
        username = random_username();
    std::cout << "Your username: " << GREEN << username << RESET << '\n';

    ssl::dtls_certificate cert;
    std::string local_fp = cert.get_fingerprint_sha256();
    std::cout << "Local DTLS fingerprint: " << local_fp << '\n';

    std::string local_ufrag = "chat_offer";
    std::string local_pwd = "chat_pwd_offer";
    if (!is_offer) {
        local_ufrag = "chat_answer";
        local_pwd = "chat_pwd_answer";
    }

    agent_config cfg = {
        .username = local_ufrag,
        .password = local_pwd,
        .ice_controlling = is_offer,
        .use_loopback = true,
        .component_count = 1,
    };
    cfg.trickle_ice = false;

    agent ag(ctx.get_executor(), cfg);

    using IceT = agent::ice_transport_type;
    using DtlsT = ssl::dtls_transport<IceT>;
    using SctpT = sctp::transport<DtlsT>;
    using DcMgr = data_channel_manager<SctpT>;
    using Datachannel = typename DcMgr::data_channel;

    auto ice = ag.create_ice_transport(1);
    auto dtls = std::make_shared<DtlsT>(ice, std::move(cert));

    struct dtls_handshake_t {
        DtlsT::handshake_type type;
        std::string setup;
    };
    dtls_handshake_t dtls_info =
        is_offer ? dtls_handshake_t{DtlsT::handshake_type::client, "active"}
                 : dtls_handshake_t{DtlsT::handshake_type::server, "passive"};

    if (is_offer) {
        std::cout << "Gathering candidates...\n";
        net::steady_timer timer(ctx, std::chrono::seconds(10));
        auto result = co_await utils::stop_when(
            ag.gather_candidates(), timer.async_wait(asio2exec::use_sender));
        if (!result.has_value()) {
            std::cout << "Gather timeout\n";
            co_return;
        }

        std::string sdp = make_sdp(ag, local_fp, dtls_info.setup, username);
        std::cout << "\n--- Copy this SDP to the answer side ---\n"
                  << enc(sdp) << "\n";
    }

    std::string remote_sdp_raw = co_await read_sdp(stdin_stream, stdin_buf);
    std::string remote_sdp_str = dec(remote_sdp_raw);
    auto remote = parse_sdp(remote_sdp_str);
    if (remote.ufrag.empty() || remote.pwd.empty()) {
        std::cout << "Invalid SDP: missing ice-ufrag or ice-pwd\n";
        co_return;
    }

    std::string remote_username = remote.username;
    if (remote_username.empty())
        remote_username = "peer";
    std::cout << "Remote: " << WHITE << remote_username << RESET
              << "  ufrag: " << remote.ufrag << "  fp: " << remote.fp
              << "  candidates: " << remote.cands.size() << '\n';

    ag.set_remote_username(remote.ufrag);
    ag.set_remote_password(remote.pwd);
    dtls->set_expected_remote_fingerprint(remote.fp);

    for (const auto &line : remote.cands) {
        auto c = candidate::from_sdp(line);
        if (c)
            co_await ag.add_remote_candidate(std::move(*c));
    }
    co_await ag.add_remote_candidate();

    if (!is_offer) {
        std::cout << "Gathering candidates...\n";
        net::steady_timer timer(ctx, std::chrono::seconds(10));
        auto result = co_await utils::stop_when(
            ag.gather_candidates(), timer.async_wait(asio2exec::use_sender));
        if (!result.has_value()) {
            std::cout << "Gather timeout\n";
            co_return;
        }

        std::string sdp = make_sdp(ag, local_fp, dtls_info.setup, username);
        std::cout << "\n--- Copy this SDP to the offer side ---\n"
                  << enc(sdp) << "\n";
    }

    std::cout << "Connecting ICE...\n";
    bool connected = co_await ag.connect();
    if (!connected) {
        std::cout << "ICE connection failed\n";
        co_return;
    }
    std::cout << "ICE connected!\n";

    std::cout << "DTLS handshake (" << dtls_info.setup << ")...\n";
    auto hs_ec = co_await dtls->async_handshake(dtls_info.type);
    if (hs_ec) {
        std::cout << "DTLS handshake failed: " << hs_ec.message() << '\n';
        co_return;
    }
    std::cout << "DTLS handshake OK\n";

    auto sctp = std::make_shared<SctpT>(dtls, exsctp::sctp_options{});
    sctp->start();

    bool sctp_connected =
        is_offer ? co_await sctp->connect() : co_await sctp->accept();
    if (!sctp_connected) {
        std::cout << "SCTP connection failed\n";
        co_return;
    }
    std::cout << "SCTP connected!\n";

    exec::async_scope scope;
    DcMgr dc_mgr(sctp, is_offer);

    dc_mgr.on_remote_channel([&](std::shared_ptr<Datachannel> ch) {
        std::cout << "Remote DataChannel: " << ch->label() << " (stream "
                  << ch->stream_id() << ")\n";
        scope.spawn([](std::shared_ptr<Datachannel> ch,
                       std::string remote_name) -> asioice::task<void> {
            while (true) {
                auto msg = co_await ch->read();
                if (!msg.binary) {
                    std::cout << WHITE << "[" << remote_name << "] " << RESET
                              << std::string_view{(const char *)msg.data.data(),
                                                  msg.data.size()}
                              << '\n';
                }
            }
        }(std::move(ch), remote_username));
    });

    dc_mgr.start();

    std::shared_ptr<Datachannel> channel =
        co_await dc_mgr.create_data_channel("chat");

    scope.spawn([](std::shared_ptr<Datachannel> ch, auto &scope,
                   net::posix::stream_descriptor &stdin, std::string &buf,
                   std::string name) -> asioice::task<void> {
        utils::scope_guard on_exit{
            [&scope]() noexcept { scope.request_stop(); }};
        while (true) {
            std::cout << GREEN << "[" << name << "] >>> " << RESET
                      << std::flush;
            auto opt = co_await read_line(stdin, buf);
            if (!opt.has_value())
                co_return;
            std::string msg = std::move(*opt);
            if (msg == "/quit")
                co_return;
            if (msg.empty())
                continue;
            bool sent = co_await ch->send_text(msg);
            if (!sent) {
                std::cout << "Send failed\n";
                co_return;
            }
        }
    }(channel, scope, stdin_stream, stdin_buf, username));

    co_await (utils::on_scope_empty(scope) | stdexec::continues_on(sched));
    std::cout << "Chat closed.\n";
}

int main() {
    net::io_context ctx;
    exec::start_detached(
        stdexec::starts_on(asio2exec::scheduler{ctx}, chat_session(ctx)));
    ctx.run();
}
