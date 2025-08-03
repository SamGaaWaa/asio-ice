#pragma once

#include <memory>
#include <iostream>

#include "config.hpp"
#include "receiver.hpp"
#include "candidate.hpp"
#include "task.hpp"
#include "stun.hpp"

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

struct candidate_pair_base {
    enum struct state {
        FROZEN = 0,
        WAITING = 1,
        IN_PROGRESS = 2,
        SUCCEEDED = 3,
        FAILED = 4
    };

    candidate_pair_base(
        ice::candidate local_candidate,
        ice::candidate remote_candidate) noexcept:
        _local_candidate(std::move(local_candidate)),
        _remote_candidate(std::move(remote_candidate))
    {
        if (!_local_candidate.transport)
            throw std::runtime_error("local candidate has no transport");
        _local_candidate.transport->connect(_remote_candidate.endpoint);
    }

    candidate_pair_base(const candidate_pair_base&) = delete;
    candidate_pair_base& operator=(const candidate_pair_base&) = delete;
    candidate_pair_base(candidate_pair_base&&) = delete;
    candidate_pair_base& operator=(candidate_pair_base&&) = delete;

    virtual ~candidate_pair_base() = default;

    virtual ice::task<bool>
    request(const stun::message& req, stun::message& res, size_t retries) = 0;

    virtual void add_receiver(ice::receiver_base& receiver) noexcept = 0;

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(std::span<net::const_buffer> data, std::shared_ptr<void> self) {
        return _local_candidate.transport->send(data, std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const void *data, std::size_t size, std::shared_ptr<void> self) {
        return _local_candidate.transport->send(data, size, std::move(self));
    }

    ice::task<std::tuple<std::error_code, std::size_t>>
    send(const net::const_buffer& data, std::shared_ptr<void> self) {
        return send(data.data(), data.size(), std::move(self));
    }
protected:
    ice::candidate _local_candidate;
    ice::candidate _remote_candidate;
    bool _nominated = false;
    bool _remote_nominated = false;
    state _state = state::FROZEN;
};

template <class StunClient>
struct candidate_pair final:
    candidate_pair_base,
    datagram_receiver<typename StunClient::endpoint_type>,
    std::enable_shared_from_this<candidate_pair<StunClient>>
{
    using endpoint_type = typename StunClient::endpoint_type;

    candidate_pair(
        ice::candidate local_candidate,
        ice::candidate remote_candidate,
        std::shared_ptr<StunClient> stun_client
    ) noexcept:
        candidate_pair_base(std::move(local_candidate), std::move(remote_candidate)),
        datagram_receiver<endpoint_type>(),
        _stun_client(std::move(stun_client)),
        _remote_endpoint(_remote_candidate.endpoint.convert_to<endpoint_type>())
    {
        _local_candidate.transport->add_receiver(*this);
    }

    const endpoint_type& remote_endpoint() const noexcept {
        return _remote_endpoint;
    }

    auto& stun_client() noexcept {
        return *_stun_client;
    }

    const auto& stun_client() const noexcept {
        return *_stun_client;
    }

    auto& receivers() noexcept {
        return _receivers;
    }

    const auto& receivers() const noexcept {
        return _receivers;
    }

    void add_receiver(datagram_receiver<endpoint_type> &receiver) noexcept {
        _receivers.push_back(receiver);
    }

    void add_receiver(ice::receiver_base& receiver) noexcept override {
        auto r = dynamic_cast<datagram_receiver<endpoint_type>*>(&receiver);
        if (!r)
            return;
        add_receiver(*r);
    }

    bool datagram_received(io_buffer_ptr &buffer, const endpoint_type &endpoint) override;

    ice::task<bool>
    request(const stun::message& req, stun::message& res, size_t retries) override;
private:
    using receiver_list_t =
        boost::intrusive::list<datagram_receiver<endpoint_type>,
                               boost::intrusive::constant_time_size<false>>;

    std::shared_ptr<StunClient> _stun_client;
    endpoint_type _remote_endpoint;
    receiver_list_t _receivers;
};

} // namespace ice

#include "impl/candidate_pair.ipp"