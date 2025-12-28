#include "candidate_pair.hpp"
#include "json.hpp"

namespace ice {

void candidate_pair::set_state(state_t state) noexcept {
    if (state == _state)
        return;
    _state = state;
    // TODO: emit event
}

void candidate_pair::set_nominated(bool nominated) noexcept {
    if (nominated == _nominated)
        return;
    _nominated = nominated;
    // TODO: emit event
}

bool candidate_pair::datagram_received(io_buffer_ptr &buffer,
                                       const ice::endpoint &endpoint) {
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
    uint64_t G = ice_controlling ? this->local_candidate().priority
                                 : this->remote_candidate().priority;
    uint64_t D = ice_controlling ? this->remote_candidate().priority
                                 : this->local_candidate().priority;
    this->_priority =
        (1llu << 32) * std::min(G, D) + 2 * std::max(G, D) + (G > D ? 1 : 0);
}

std::string candidate_pair::to_string(int indent) const {
    nlohmann::json local, remote;

    local["foundation"] = this->local_candidate().foundation;
    local["component"] = this->local_candidate().component;
    local["transport"] = this->local_candidate().transport_type;
    local["priority"] = this->local_candidate().priority;
    local["endpoint"] = this->local_candidate().endpoint.to_string();
    local["type"] = ice::to_string(this->local_candidate().type);

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
    remote["type"] = ice::to_string(this->remote_candidate().type);

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
    res["nominated"] = this->_nominated;
    res["remote_nominated"] = this->_remote_nominated;
    return res.dump(indent);
}

} // namespace ice