#include "asioice/agent.hpp"
#include "asioice/impl/basic_agent_impl.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#include <boost/asio/ip/udp.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include <asio/ip/udp.hpp>
namespace asioice {
namespace net = asio;
}
#endif

namespace asioice {

using udp_agent_impl = impl::basic_agent_impl<net::ip::udp::socket>;

agent::agent(agent::executor_type ex, agent_config config)
    : _impl(new udp_agent_impl(std::move(ex), std::move(config))) {}

agent::agent(agent &&other) noexcept
    : _impl{std::exchange(other._impl, nullptr)} {}

agent &agent::operator=(agent &&other) noexcept {
    if (this != &other) {
        delete static_cast<udp_agent_impl *>(_impl);
        _impl = std::exchange(other._impl, nullptr);
    }
    return *this;
}

agent::~agent() noexcept { delete static_cast<udp_agent_impl *>(_impl); }

agent::executor_type agent::get_executor() const {
    return static_cast<udp_agent_impl *>(_impl)->get_executor();
}

std::span<const asioice::candidate> agent::local_candidates() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->local_candidates();
}

std::span<const asioice::candidate> agent::remote_candidates() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->remote_candidates();
}

const agent_config &agent::config() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->config();
}

const std::vector<std::shared_ptr<asioice::candidate_pair>> &
agent::candidate_pairs() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->candidate_pairs();
}

const std::string &agent::local_username() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->local_username();
}

const std::string &agent::local_password() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->local_password();
}

const std::string &agent::remote_username() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->remote_username();
}

void agent::set_remote_username(std::string username) noexcept {
    static_cast<udp_agent_impl *>(_impl)->set_remote_username(
        std::move(username));
}

const std::string &agent::remote_password() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->remote_password();
}

void agent::set_remote_password(std::string password) noexcept {
    static_cast<udp_agent_impl *>(_impl)->set_remote_password(
        std::move(password));
}

agent_state_t agent::state() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->state();
}

asioice::task<void> agent::on_state_change() noexcept {
    co_return co_await static_cast<udp_agent_impl *>(_impl)->on_state_change();
}

asioice::task<void> agent::on_closed() noexcept {
    co_return co_await static_cast<udp_agent_impl *>(_impl)->on_closed();
}

asioice::task<void> agent::on_connected_or_closed() noexcept {
    co_return co_await static_cast<udp_agent_impl *>(_impl)
        ->on_connected_or_closed();
}

bool agent::all_components_nominated() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)->all_components_nominated();
}

bool agent::all_components_have_valid_pair() const noexcept {
    return static_cast<udp_agent_impl *>(_impl)
        ->all_components_have_valid_pair();
}

asioice::task<void> agent::gather_candidates() {
    return static_cast<udp_agent_impl *>(_impl)->gather_candidates();
}

asioice::task<bool> agent::add_remote_candidate(asioice::candidate c) {
    return static_cast<udp_agent_impl *>(_impl)->add_remote_candidate(
        std::move(c));
}

asioice::task<void> agent::add_remote_candidate() {
    co_await static_cast<udp_agent_impl *>(_impl)->add_remote_candidate();
}

asioice::task<bool> agent::connect() {
    return static_cast<udp_agent_impl *>(_impl)->connect();
}

boost::container::small_vector<asioice::candidate_pair *, 2>
agent::nominated_pairs() const {
    return static_cast<udp_agent_impl *>(_impl)->nominated_pairs();
}

void agent::on_local_candidates(
    boost::compat::move_only_function<void(std::span<const asioice::candidate>)>
        cb) {
    static_cast<udp_agent_impl *>(_impl)->on_local_candidates(std::move(cb));
}

asioice::task<std::tuple<std::error_code, std::size_t>>
agent::sendto(net::const_buffer data, uint8_t component) {
    co_return co_await static_cast<udp_agent_impl *>(_impl)->sendto(data,
                                                                    component);
}

void agent::on_data(
    boost::compat::move_only_function<void(asioice::io_buffer_ptr, uint8_t)>
        callback) {
    static_cast<udp_agent_impl *>(_impl)->on_data(std::move(callback));
}

void agent::close() noexcept { static_cast<udp_agent_impl *>(_impl)->close(); }

} // namespace asioice