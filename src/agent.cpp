#include "asioice/agent.hpp"
#include "asioice/impl/basic_agent_impl.hpp"
#include "asioice/impl/ice_transport.hpp"

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
    : _impl(
          std::make_shared<udp_agent_impl>(std::move(ex), std::move(config))) {}

agent::agent(agent &&other) noexcept
    : _impl{std::exchange(other._impl, nullptr)} {}

agent &agent::operator=(agent &&other) noexcept {
    if (this != &other) {
        _impl = std::move(other._impl);
    }
    return *this;
}

agent::~agent() noexcept {}

agent::executor_type agent::get_executor() const {
    return static_cast<udp_agent_impl *>(_impl.get())->get_executor();
}

std::span<const asioice::candidate> agent::local_candidates() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->local_candidates();
}

std::span<const asioice::candidate> agent::remote_candidates() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->remote_candidates();
}

const agent_config &agent::config() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->config();
}

const std::vector<std::shared_ptr<asioice::candidate_pair>> &
agent::candidate_pairs() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->candidate_pairs();
}

const std::string &agent::local_username() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->local_username();
}

const std::string &agent::local_password() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->local_password();
}

const std::string &agent::remote_username() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->remote_username();
}

void agent::set_remote_username(std::string username) noexcept {
    static_cast<udp_agent_impl *>(_impl.get())
        ->set_remote_username(std::move(username));
}

const std::string &agent::remote_password() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->remote_password();
}

void agent::set_remote_password(std::string password) noexcept {
    static_cast<udp_agent_impl *>(_impl.get())
        ->set_remote_password(std::move(password));
}

agent_state_t agent::state() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())->state();
}

asioice::task<void> agent::on_state_change() noexcept {
    co_return co_await static_cast<udp_agent_impl *>(_impl.get())
        ->on_state_change();
}

asioice::task<void> agent::on_closed() noexcept {
    co_return co_await static_cast<udp_agent_impl *>(_impl.get())->on_closed();
}

asioice::task<void> agent::on_connected_or_closed() noexcept {
    co_return co_await static_cast<udp_agent_impl *>(_impl.get())
        ->on_connected_or_closed();
}

bool agent::all_components_nominated() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())
        ->all_components_nominated();
}

bool agent::all_components_have_valid_pair() const noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())
        ->all_components_have_valid_pair();
}

asioice::task<void> agent::gather_candidates() {
    return static_cast<udp_agent_impl *>(_impl.get())->gather_candidates();
}

asioice::task<bool> agent::add_remote_candidate(asioice::candidate c) {
    return static_cast<udp_agent_impl *>(_impl.get())
        ->add_remote_candidate(std::move(c));
}

asioice::task<void> agent::add_remote_candidate() {
    co_await static_cast<udp_agent_impl *>(_impl.get())->add_remote_candidate();
}

asioice::task<bool> agent::connect() {
    return static_cast<udp_agent_impl *>(_impl.get())->connect();
}

boost::container::small_vector<asioice::candidate_pair *, 2>
agent::nominated_pairs() const {
    return static_cast<udp_agent_impl *>(_impl.get())->nominated_pairs();
}

void agent::on_local_candidates(
    boost::compat::move_only_function<void(std::span<const asioice::candidate>)>
        cb) {
    static_cast<udp_agent_impl *>(_impl.get())
        ->on_local_candidates(std::move(cb));
}

asioice::task<std::tuple<std::error_code, std::size_t>>
agent::sendto(net::const_buffer data, uint8_t component) {
    co_return co_await static_cast<udp_agent_impl *>(_impl.get())
        ->sendto(data, component);
}

asioice::task<std::tuple<std::error_code, std::size_t>>
agent::sendto(std::span<const net::const_buffer> data, uint8_t component) {
    co_return co_await static_cast<udp_agent_impl *>(_impl.get())
        ->sendto(data, component);
}

void agent::on_data(
    boost::compat::move_only_function<void(asioice::io_buffer_ptr &, uint8_t)>
        callback) {
    static_cast<udp_agent_impl *>(_impl.get())->on_data(std::move(callback));
}

bool agent::restart(std::string new_ufrag, std::string new_pwd) noexcept {
    return static_cast<udp_agent_impl *>(_impl.get())
        ->restart(std::move(new_ufrag), std::move(new_pwd));
}

void agent::close() noexcept {
    static_cast<udp_agent_impl *>(_impl.get())->close();
}

void agent::add_receiver(ice_receiver &receiver) {
    static_cast<udp_agent_impl *>(_impl.get())->add_receiver(receiver);
}

void agent::remove_receiver(ice_receiver &receiver) noexcept {
    static_cast<udp_agent_impl *>(_impl.get())->remove_receiver(receiver);
}

struct agent_ice_transport_type final : agent::ice_transport_type {
    agent_ice_transport_type(std::shared_ptr<udp_agent_impl> impl,
                             uint8_t component)
        : _transport(std::move(impl), component) {}

    net::any_io_executor get_executor() const noexcept override {
        return _transport.get_executor();
    }

    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_send(net::const_buffer data) override {
        co_return co_await _transport.async_send(data);
    }
    asioice::task<std::tuple<std::error_code, std::size_t>>
    async_send(std::span<const net::const_buffer> data) override {
        co_return co_await _transport.async_send(data);
    }
    uint8_t component() const noexcept override {
        return _transport.component();
    }
    void add_receiver(asioice::datagram_receiver &receiver) override {
        _transport.add_receiver(receiver);
    }

  private:
    impl::ice_transport<udp_agent_impl> _transport;
};

std::shared_ptr<agent::ice_transport_type>
agent::create_ice_transport(uint8_t component) {
    return std::make_shared<agent_ice_transport_type>(
        std::static_pointer_cast<udp_agent_impl>(_impl), component);
}

} // namespace asioice