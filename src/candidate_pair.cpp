#include "asioice/candidate_pair.hpp"
#include "asioice/detail/scope_guard.hpp"
#include "asioice/detail/stun.hpp"
#include "asioice/detail/asio2exec.hpp"
#include "samlog.hpp"

#include "json.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <cassert>

namespace asioice {

void candidate_pair::set_state(state_t state) noexcept {
    if (state == _state)
        return;
    _state = state;
    // TODO: emit event
}

bool candidate_pair::datagram_received(io_buffer_ptr &buffer,
                                       const asioice::endpoint &endpoint) {
    if (!buffer) [[unlikely]] // ignore empty buffers
        return true;
    const uint8_t first_byte = *buffer->begin();
    if (first_byte <= 3) [[unlikely]] {
        // STUN
        return false;
    }
    if (first_byte >= 64 && first_byte <= 79) [[unlikely]] {
        // TURN channel, ignore
        return false;
    }
    if (endpoint != this->remote_candidate().endpoint)
        return false;
    // application data
    dispatch_receivers(this->receivers(), buffer, endpoint);
    return true;
}

void candidate_pair::set_priority(bool ice_controlling) noexcept {
    this->_priority = compute_priority(local_candidate(), remote_candidate(),
                                       ice_controlling);
}

uint64_t candidate_pair::compute_priority(const asioice::candidate &local,
                                          const asioice::candidate &remote,
                                          bool ice_controlling) noexcept {
    uint64_t G = ice_controlling ? local.priority : remote.priority;
    uint64_t D = ice_controlling ? remote.priority : local.priority;
    return (1llu << 32) * std::min(G, D) + 2 * std::max(G, D) + (G > D ? 1 : 0);
}

std::string candidate_pair::to_string(int indent) const {
    nlohmann::json local, remote;

    local["foundation"] = this->local_candidate().foundation;
    local["component"] = this->local_candidate().component;
    local["transport"] = this->local_candidate().transport_type;
    local["priority"] = this->local_candidate().priority;
    local["endpoint"] = this->local_candidate().endpoint.to_string();
    local["type"] = asioice::type_to_string(this->local_candidate().type);

    if (this->local_candidate().related) {
        local["related"] = this->local_candidate().related->to_string();
    }
    if (!this->local_candidate().tcptype.empty()) {
        local["tcptype"] = this->local_candidate().tcptype;
    }
    if (this->local_candidate().generation) {
        local["generation"] = *this->local_candidate().generation;
    }

    remote["foundation"] = this->remote_candidate().foundation;
    remote["component"] = this->remote_candidate().component;
    remote["transport"] = this->remote_candidate().transport_type;
    remote["priority"] = this->remote_candidate().priority;
    remote["endpoint"] = this->remote_candidate().endpoint.to_string();
    remote["type"] = asioice::type_to_string(this->remote_candidate().type);

    if (!this->remote_candidate().tcptype.empty()) {
        remote["tcptype"] = this->remote_candidate().tcptype;
    }
    if (this->remote_candidate().generation) {
        remote["generation"] = *this->remote_candidate().generation;
    }

    nlohmann::json res;
    res["local"] = std::move(local);
    res["remote"] = std::move(remote);
    res["priority"] = this->priority();
    res["state"] = [](auto state) noexcept {
        switch (state) {
        case candidate_pair::state_t::FROZEN:
            return "FROZEN";
        case candidate_pair::state_t::WAITING:
            return "WAITING";
        case candidate_pair::state_t::IN_PROGRESS:
            return "IN_PROGRESS";
        case candidate_pair::state_t::SUCCEEDED:
            return "SUCCESSED";
        case candidate_pair::state_t::FAILED:
            return "FAILED";
        default:
            return "";
        }
    }(this->_state);
    return res.dump(indent);
}

asioice::task<void>
candidate_pair::keepalive_task(std::chrono::milliseconds ms,
                               std::weak_ptr<candidate_pair> self) {
    net::any_io_executor ex;
    if (auto p = self.lock(); !p || p->_keepalive_started)
        co_return;
    else {
        SAMLOG_INFO(auto sink) { sink("Keepalive task started\n"); };
        p->_keepalive_started = true;
        ex = p->local_candidate().transport.get_executor();
    }
    utils::scope_guard on_exit([&]() noexcept {
        auto p = self.lock();
        if (!p)
            return;
        SAMLOG_INFO(auto sink) { sink("Keepalive task exited\n"); };
        p->_keepalive_started = false;
    });

    net::steady_timer timer{ex};
    while (true) {
        auto p = self.lock();
        if (!p)
            co_return;
        while (true) {
            const auto now = std::chrono::steady_clock::now();
            const auto send_time = p->last_keepalive_time() + ms;
            if (send_time <= now)
                break;
            p = nullptr;
            timer.expires_at(send_time);
            co_await timer.async_wait(utils::use_sender);
            p = self.lock();
            if (!p)
                co_return;
        }

        stun::message msg;
        msg.cls = stun::class_t::STUN_CLASS_INDICATION;
        msg.method = stun::method_t::STUN_METHOD_BINDING;
        msg.use_fingerprint(true);

        char buf[1024];
        int n = msg.write_to(buf, sizeof(buf));
        assert(n > 0);

        auto transport = p->local_candidate().transport;
        auto dst = p->remote_candidate().endpoint;
        p = nullptr;
        auto [ec, _] =
            co_await transport.async_send_to(net::buffer(buf, n), dst);
        if (ec)
            co_return;
        p = self.lock();
        if (!p)
            co_return;
        SAMLOG_INFO(auto sink) { sink("Sent keepalive indication\n"); };
        p->update_keepalive_time();
    }
}

} // namespace asioice