#include "agent_base_impl.hpp"

namespace asioice {

agent_base::agent_base(net::any_io_executor ex, agent_config config)
    : _impl(std::make_shared<agent_base_impl>(std::move(ex), std::move(config),
                                              this)) {}

agent_base::~agent_base() { close(); }

std::span<const asioice::candidate>
agent_base::local_candidates() const noexcept {
    return _impl->local_candidates();
}

std::span<const asioice::candidate>
agent_base::remote_candidates() const noexcept {
    return _impl->remote_candidates();
}

const agent_config &agent_base::config() const noexcept {
    return _impl->config();
}

agent_config &agent_base::config() noexcept { return _impl->config(); }

const std::vector<std::shared_ptr<asioice::candidate_pair>> &
agent_base::candidate_pairs() const noexcept {
    return _impl->candidate_pairs();
}

const std::string &agent_base::local_username() const noexcept {
    return _impl->local_username();
}

const std::string &agent_base::local_password() const noexcept {
    return _impl->local_password();
}

const std::string &agent_base::remote_username() const noexcept {
    return _impl->remote_username();
}

void agent_base::set_remote_username(std::string username) noexcept {
    _impl->set_remote_username(std::move(username));
}

const std::string &agent_base::remote_password() const noexcept {
    return _impl->remote_password();
}

void agent_base::set_remote_password(std::string password) noexcept {
    _impl->set_remote_password(std::move(password));
}

void agent_base::set_remote_is_lite(bool lite) noexcept {
    _impl->set_remote_is_lite(lite);
}

std::shared_ptr<io_buffer_pool> &agent_base::buffer_pool() noexcept {
    return _impl->buffer_pool();
}

const std::shared_ptr<io_buffer_pool> &
agent_base::buffer_pool() const noexcept {
    return _impl->buffer_pool();
}

agent_state_t agent_base::state() const noexcept { return _impl->state(); }
exec::function<void()> agent_base::on_state_change() noexcept {
    return exec::function<void()>{[this] { return _impl->on_state_change(); }};
}

exec::function<void()> agent_base::on_closed() noexcept {
    return exec::function<void()>{[this] { return _impl->on_closed(); }};
}

exec::function<void()> agent_base::on_connected_or_closed() noexcept {
    return exec::function<void()>{
        [this] { return _impl->on_connected_or_closed(); }};
}

bool agent_base::restart(std::string new_ufrag,
                         std::string new_pwd) noexcept {
    return _impl->restart(std::move(new_ufrag), std::move(new_pwd));
}

void agent_base::close() noexcept { _impl->close(); }

bool agent_base::all_components_nominated() const noexcept {
    return _impl->all_components_nominated();
}

bool agent_base::all_components_have_valid_pair() const noexcept {
    return _impl->all_components_have_valid_pair();
}

asioice::task<void> agent_base::gather_candidates() {
    co_await _impl->gather_candidates();
}

asioice::task<bool> agent_base::add_remote_candidate(asioice::candidate c) {
    return _impl->add_remote_candidate(std::move(c));
}

exec::function<bool()> agent_base::add_remote_candidate() noexcept {
    return exec::function<bool()>{
        [this] { return _impl->add_remote_candidate(); }};
}

asioice::task<bool> agent_base::connect() {
    co_await _impl->connect();
    co_return this->state() == agent_state_t::CONNECTED;
}

boost::container::small_vector<asioice::candidate_pair *, 2>
agent_base::nominated_pairs() const {
    return _impl->nominated_pairs();
}

void agent_base::on_local_candidates(
    boost::compat::move_only_function<void(std::span<const asioice::candidate>)>
        cb) {
    _impl->on_local_candidates(std::move(cb));
}

void agent_base::on_data(
    boost::compat::move_only_function<void(asioice::io_buffer_ptr &, uint8_t)>
        callback) {
    _impl->on_data(std::move(callback));
}

std::shared_ptr<asioice::candidate_pair>
agent_base::find_nominated_pair(uint8_t component) const noexcept {
    return _impl->find_nominated_pair(component);
}

void agent_base::add_receiver(ice_receiver &receiver) noexcept {
    _impl->add_receiver(receiver);
}

void agent_base::remove_receiver(ice_receiver &receiver) noexcept {
    _impl->remove_receiver(receiver);
}

} // namespace asioice
