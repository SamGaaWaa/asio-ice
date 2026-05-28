#pragma once

#include "config.hpp"
#include "address.hpp"
#include "any_transport.hpp"
#include "agent_config.hpp"
#include "candidate_pair.hpp"
#include "task.hpp"
#include "turn_interface.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/any_io_executor.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/any_io_executor.hpp>
namespace asioice {
namespace net = asio;
}
#endif

#include <exec/function.hpp>

#include <boost/container/small_vector.hpp>
#include <boost/compat/move_only_function.hpp>

#include <memory>
#include <span>
#include <vector>
#include <string>
#include <string_view>

namespace asioice {

struct agent_base_impl;

enum struct agent_state_t : char {
    INIT,
    GATHERING,
    CONNECTING,
    CONNECTED,
    CLOSED
};

struct agent_base {
    // interface need to be overridden by agent_impl
    virtual any_transport
    base_create_socket_transport(const net::ip::address &local_addr) = 0;
    virtual std::shared_ptr<turn::turn_interface> base_create_turn_client(
        any_transport &socket_transport, const asioice::endpoint &server,
        std::string_view username, std::string_view password) = 0;
    virtual any_transport base_create_turn_transport(
        std::shared_ptr<turn::turn_interface> client) = 0;

    agent_base(net::any_io_executor executor, asioice::agent_config config);

    agent_base(const agent_base &) = delete;
    agent_base &operator=(const agent_base &) = delete;
    agent_base(agent_base &&) = delete;
    agent_base &operator=(agent_base &&) = delete;

    virtual ~agent_base();

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
    exec::function<void()> on_state_change() noexcept;

    exec::function<void()> on_closed() noexcept;

    exec::function<void()> on_connected_or_closed() noexcept;

    void close() noexcept;

    bool all_components_nominated() const noexcept;
    bool all_components_have_valid_pair() const noexcept;

    asioice::task<void> gather_candidates();

    asioice::task<bool> add_remote_candidate(asioice::candidate c);
    exec::function<bool()> add_remote_candidate() noexcept;

    asioice::task<bool> connect() noexcept;

    boost::container::small_vector<asioice::candidate_pair *, 2>
    nominated_pairs() const;

    void on_local_candidates(boost::compat::move_only_function<
                             void(std::span<const asioice::candidate>)>
                                 cb);

    void on_data(
        boost::compat::move_only_function<void(asioice::io_buffer_ptr, uint8_t)>
            callback);

    std::shared_ptr<asioice::candidate_pair>
    find_nominated_pair(uint8_t component) const noexcept;

  private:
    std::shared_ptr<agent_base_impl> _impl;
};

} // namespace asioice