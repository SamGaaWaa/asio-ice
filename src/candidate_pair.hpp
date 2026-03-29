#pragma once

#include <memory>
#include <functional>
#include <iostream>

#include <boost/intrusive/list.hpp>
#include <boost/intrusive/set.hpp>

#include "config.hpp"
#include "receiver.hpp"
#include "candidate.hpp"
#include "task.hpp"
#include "stun.hpp"
#include "stun_transaction.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/buffer.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"

namespace ice {

// struct __triggered_check_queue_tag;
// using __triggered_check_queue_base_hook = boost::intrusive::list_base_hook<
//     boost::intrusive::tag<__triggered_check_queue_tag>,
//     boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;

struct candidate_pair final
    : datagram_receiver,
      std::enable_shared_from_this<ice::candidate_pair> {

    enum struct state_t {
        FROZEN = 0,
        WAITING = 1,
        IN_PROGRESS = 2,
        SUCCEEDED = 3,
        FAILED = 4
    };

    using request_handler_type =
        std::function<void(const ice::endpoint &from, const ice::endpoint &to,
                           ice::io_buffer_ptr)>;

    candidate_pair(ice::candidate local_candidate,
                   ice::candidate remote_candidate)
        : datagram_receiver(), _local_candidate(std::move(local_candidate)),
          _remote_candidate(std::move(remote_candidate)) {
        if (!_local_candidate.transport)
            throw std::runtime_error("local candidate has no transport");
        if (_local_candidate.foundation > _remote_candidate.foundation)
            _foundation =
                _remote_candidate.foundation + _local_candidate.foundation;
        else
            _foundation =
                _local_candidate.foundation + _remote_candidate.foundation;
        _local_candidate.transport.add_receiver(*this);
    }

    auto &receivers() noexcept { return _receivers; }

    const auto &receivers() const noexcept { return _receivers; }

    void add_receiver(datagram_receiver &receiver) noexcept {
        _receivers.push_back(receiver);
    }

    bool datagram_received(io_buffer_ptr &buffer,
                           const ice::endpoint &endpoint) override;

    const auto &local_candidate() const noexcept { return _local_candidate; }
    const auto &remote_candidate() const noexcept { return _remote_candidate; }

    uint64_t priority() const noexcept { return _priority; }
    void set_priority(bool ice_controlling) noexcept;
    void set_priority(uint64_t priority) noexcept {
        this->_priority = priority;
    }
    static uint64_t compute_priority(const ice::candidate &local,
                                     const ice::candidate &remote,
                                     bool ice_controlling) noexcept;

    state_t state() const noexcept { return _state; }
    void set_state(state_t state) noexcept;

    // bool nominated() const noexcept { return _nominated; }
    // void set_nominated(bool nominated) noexcept;

    const std::string &foundation() const noexcept {
        // TODO: What is candidate pair foundation?
        return _foundation;
    }

    auto component() const noexcept { return _local_candidate.component; }
    const std::string &transport_type() const noexcept {
        return _local_candidate.transport_type;
    }

    // bool in_triggered_queue() const noexcept {
    //     return __triggered_check_queue_base_hook::is_linked();
    // }

    template <class BufferSequence>
    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const BufferSequence &data) {
        return _local_candidate.transport.send_to(data,
                                                  _remote_candidate.endpoint);
    }

    ice::task<std::tuple<std::error_code, std::size_t>> send(const void *data,
                                                             std::size_t size) {
        return _local_candidate.transport.send_to(data, size,
                                                  _remote_candidate.endpoint);
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const net::const_buffer &data) {
        return send(data.data(), data.size());
    }

    std::string to_string(int indent = 4) const;

  private:
    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    ice::candidate _local_candidate;
    ice::candidate _remote_candidate;
    std::string _foundation;
    uint64_t _priority{};
    // bool _nominated = false;
    // bool _remote_nominated = false;
    state_t _state = state_t::FROZEN;
    receiver_list_t _receivers{};
};

} // namespace ice