#pragma once

#include "asioice/config.hpp"
#include "asioice/candidate_pair.hpp"
#include "asioice/agent_config.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/receiver.hpp"
#include "asioice/agent_state.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/any_io_executor.hpp>
#include <asio/buffer.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <boost/container/small_vector.hpp>
#include <boost/compat/move_only_function.hpp>

namespace asioice {

struct agent {
    using executor_type = net::any_io_executor;

    struct ice_transport_type {
        using executor_type = net::any_io_executor;
        virtual net::any_io_executor get_executor() const noexcept = 0;
        virtual asioice::task<std::tuple<std::error_code, std::size_t>>
        async_send(net::const_buffer data) = 0;
        virtual asioice::task<std::tuple<std::error_code, std::size_t>>
        async_send(std::span<const net::const_buffer> data) = 0;
        virtual uint8_t component() const noexcept = 0;
        virtual void add_receiver(asioice::datagram_receiver &receiver) = 0;
        virtual ~ice_transport_type() = default;
    };

    agent(executor_type ex, agent_config config);

    agent(const agent &) = delete;
    agent &operator=(const agent &) = delete;
    agent(agent &&other) noexcept;
    agent &operator=(agent &&other) noexcept;

    ~agent() noexcept;

    executor_type get_executor() const;

    std::span<const asioice::candidate> local_candidates() const noexcept;

    std::span<const asioice::candidate> remote_candidates() const noexcept;

    const agent_config &config() const noexcept;

    const std::vector<std::shared_ptr<asioice::candidate_pair>> &
    candidate_pairs() const noexcept;

    const std::string &local_username() const noexcept;

    const std::string &local_password() const noexcept;

    const std::string &remote_username() const noexcept;

    void set_remote_username(std::string username) noexcept;

    const std::string &remote_password() const noexcept;

    void set_remote_password(std::string password) noexcept;

    agent_state_t state() const noexcept;

    asioice::task<void> on_state_change() noexcept;

    asioice::task<void> on_closed() noexcept;

    asioice::task<void> on_connected_or_closed() noexcept;

    bool all_components_nominated() const noexcept;

    bool all_components_have_valid_pair() const noexcept;

    asioice::task<void> gather_candidates();

    asioice::task<bool> add_remote_candidate(asioice::candidate c);

    asioice::task<void> add_remote_candidate();

    asioice::task<bool> connect();

    boost::container::small_vector<asioice::candidate_pair *, 2>
    nominated_pairs() const;

    void on_local_candidates(boost::compat::move_only_function<
                             void(std::span<const asioice::candidate>)>
                                 cb);

    asioice::task<std::tuple<std::error_code, std::size_t>>
    sendto(net::const_buffer data, uint8_t component);

    asioice::task<std::tuple<std::error_code, std::size_t>>
    sendto(std::span<const net::const_buffer> data, uint8_t component);

    void on_data(boost::compat::move_only_function<
                 void(asioice::io_buffer_ptr &, uint8_t)>
                     callback);

    void close() noexcept;

    void add_receiver(ice_receiver &receiver);
    void remove_receiver(ice_receiver &receiver) noexcept;

    std::shared_ptr<ice_transport_type> create_ice_transport(uint8_t component);

  private:
    std::shared_ptr<void> _impl;
};

} // namespace asioice