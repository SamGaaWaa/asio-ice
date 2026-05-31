#pragma once

#include "asioice/config.hpp"
#include "asioice/detail/receiver.hpp"

#include <memory>
#include <stdexcept>

namespace asioice::impl {

template <class Agent> struct ice_transport final : asioice::ice_receiver {
    using agent_type = Agent;
    using executor_type = typename agent_type::executor_type;

    ice_transport(std::shared_ptr<agent_type> agent, uint8_t component)
        : _agent(std::move(agent)), _component(component) {
        if (!_agent)
            throw std::invalid_argument("agent cannot be null");
        _agent->add_receiver(*this);
    }

    ice_transport(const ice_transport &) = delete;
    ice_transport &operator=(const ice_transport &) = delete;
    ice_transport(ice_transport &&) = delete;
    ice_transport &operator=(ice_transport &&) = delete;

    ~ice_transport() { _agent->remove_receiver(*this); }

    executor_type get_executor() const noexcept {
        return _agent->get_executor();
    }

    uint8_t component() const noexcept override { return _component; }

    template <class ConstBufferSequence>
    auto async_send(ConstBufferSequence buffers) {
        return _agent->sendto(buffers, _component);
    }

    void add_receiver(datagram_receiver &receiver) {
        _receivers.push_back(receiver);
    }

  private:
    void data_received(io_buffer_ptr buffer) override {
        dispatch_receivers(_receivers, buffer);
    }

    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    std::shared_ptr<agent_type> _agent;
    uint8_t _component;
    receiver_list_t _receivers{};
};

} // namespace asioice::impl