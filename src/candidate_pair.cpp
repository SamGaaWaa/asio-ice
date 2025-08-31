#include "candidate_pair.hpp"
#include "json.hpp"

namespace ice {

void candidate_pair_base::set_priority(bool ice_controlling) noexcept {
    uint64_t G = ice_controlling ? this->local_candidate().priority
                                 : this->remote_candidate().priority;
    uint64_t D = ice_controlling ? this->remote_candidate().priority
                                 : this->local_candidate().priority;
    this->_priority =
        (1llu << 32) * std::min(G, D) + 2 * std::max(G, D) + (G > D ? 1 : 0);
}

std::string candidate_pair_base::to_string(int indent) const {
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
        case candidate_pair_base::state_t::FROZEN:
            return "FROZEN";
        case candidate_pair_base::state_t::WAITING:
            return "WAITING";
        case candidate_pair_base::state_t::IN_PROGRESS:
            return "IN_PROGRESS";
        case candidate_pair_base::state_t::SUCCEEDED:
            return "SUCCESSED";
        case candidate_pair_base::state_t::FAILED:
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