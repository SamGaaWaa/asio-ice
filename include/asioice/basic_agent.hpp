#pragma once

#include "asioice/impl/basic_agent_impl.hpp"

namespace asioice {

template <class Sock> struct basic_agent {
    using impl_type = asioice::impl::basic_agent_impl<Sock>;
    using socket_type = Sock;
    using executor_type = typename socket_type::executor_type;

    basic_agent(executor_type ex, agent_config config)
        : _impl(std::make_unique<impl_type>(std::move(ex), std::move(config))) {
    }

    basic_agent(const basic_agent &) = delete;
    basic_agent &operator=(const basic_agent &) = delete;
    basic_agent(basic_agent &&other) noexcept = default;
    basic_agent &operator=(basic_agent &&other) noexcept = default;

    executor_type get_executor() const noexcept {
        return _impl->get_executor();
    }

    std::span<const asioice::candidate> local_candidates() const noexcept {
        return _impl->local_candidates();
    }

    std::span<const asioice::candidate> remote_candidates() const noexcept {
        return _impl->remote_candidates();
    }

    const agent_config &config() const noexcept { return _impl->config(); }

    const std::vector<std::shared_ptr<asioice::candidate_pair>> &
    candidate_pairs() const noexcept {
        return _impl->candidate_pairs();
    }

    const std::string &local_username() const noexcept {
        return _impl->local_username();
    }

    const std::string &local_password() const noexcept {
        return _impl->local_password();
    }

    const std::string &remote_username() const noexcept {
        return _impl->remote_username();
    }

    void set_remote_username(std::string username) noexcept {
        _impl->set_remote_username(std::move(username));
    }

    const std::string &remote_password() const noexcept {
        return _impl->remote_password();
    }

    void set_remote_password(std::string password) noexcept {
        _impl->set_remote_password(std::move(password));
    }

    agent_state_t state() const noexcept { return _impl->state(); }

    auto on_state_change() noexcept { return _impl->on_state_change(); }

    auto on_closed() noexcept { return _impl->on_closed(); }

    auto on_connected_or_closed() noexcept {
        return _impl->on_connected_or_closed();
    }

    bool all_components_nominated() const noexcept {
        return _impl->all_components_nominated();
    }

    bool all_components_have_valid_pair() const noexcept {
        return _impl->all_components_have_valid_pair();
    }

    asioice::task<void> gather_candidates() {
        return _impl->gather_candidates();
    }

    asioice::task<bool> add_remote_candidate(asioice::candidate c) {
        return _impl->add_remote_candidate(std::move(c));
    }

    auto add_remote_candidate() noexcept {
        return _impl->add_remote_candidate();
    }

    asioice::task<bool> connect() noexcept { return _impl->connect(); }

    boost::container::small_vector<asioice::candidate_pair *, 2>
    nominated_pairs() const {
        return _impl->nominated_pairs();
    }

    template <class Func> void on_local_candidates(Func &&cb) {
        _impl->on_local_candidates(std::forward<Func>(cb));
    }

    auto sendto(net::const_buffer data, uint8_t component) {
        return _impl->sendto(data, component);
    }

    template <class Func>
        requires(std::invocable<Func, asioice::io_buffer_ptr, uint8_t>)
    void on_data(Func &&callback) {
        _impl->on_data(std::forward<Func>(callback));
    }

    void close() { _impl->close(); }

  private:
    std::unique_ptr<impl_type> _impl;
};

} // namespace asioice