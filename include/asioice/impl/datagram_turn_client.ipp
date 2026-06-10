namespace asioice::turn::impl {

template <class NextLayer>
asioice::task<bool> datagram_client<NextLayer>::request(
    const stun::message &req, asioice::endpoint &from, stun::message &resp,
    std::size_t retries, auto... self) noexcept {
    auto it = this->_transactions.lower_bound(req.transaction_id);
    if (it != this->_transactions.end() &&
        it->request.transaction_id == req.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return false;
    }
    stun::transaction trans(this->get_executor(), req, this->_server, resp);
    this->_transactions.insert(it, trans);

    bool ret = false;
    utils::inplace_receiver<void> retry_receiver;
    utils::scheduler sched{this->get_executor()};
    auto retry_op = retry_receiver.start(
        stdexec::starts_on(sched, trans.run(this->_next_layer)));
    stdexec::start(retry_op);

    while (true) {
        ret = false;
        auto new_state =
            co_await (trans.on_state_change() | stdexec::continues_on(sched) |
                      stdexec::stopped_as_optional());
        if (!new_state.has_value()) {
            goto END;
        }
        if (trans.state() == stun::transaction::state_t::ERR) {
            goto END;
        }
        assert(trans.state() == stun::transaction::state_t::DONE);
        assert(resp.transaction_id == req.transaction_id);
        assert(resp.is_response());
        if (resp.cls == stun::class_t::STUN_CLASS_RESP_ERROR) {
            // If the error response contains unknown comprehension-required
            // attributes, or if the error response does not contain an
            // ERROR-CODE attribute, then the transaction is simply considered
            // to have failed.
            if (!resp.error_code.has_value()) {
                goto END;
            }
            if (resp.error_code->code == 401 || resp.error_code->code == 438) {
                ret = true;
                goto END;
            }
            // If the response is an error response with an error code of 400
            // (Bad Request) and does not contain either the MESSAGE-INTEGRITY
            // or MESSAGE-INTEGRITY-SHA256 attribute, then the response MUST be
            // discarded, as if it were never received.  This means that
            // retransmits, if applicable, will continue.
            if (resp.error_code->code == 400 && resp.integrities.empty()) {
                continue;
            }
        }
        // For all other responses, if the NONCE attribute starts with the
        // "nonce cookie" with the STUN Security Feature "Password algorithms"
        // bit set to 1 but PASSWORD-ALGORITHMS is not present, the response
        // MUST be ignored.
        if (resp.nonce.starts_with(stun::STUN_NONCE_COOKIE) &&
            (resp.security_features() & 0x01) && resp.pwd_algorithms.empty()) {
            continue;
        }
        // The client looks for the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-
        // SHA256 attribute in the response (either success or failure).  If
        // present, the client computes the message integrity over the response
        // as defined in Sections 14.5 or 14.6, using the same password it
        // utilized for the request.  If the resulting value matches the
        // contents of the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
        // attribute, the response is considered authenticated.  If the value
        // does not match, or if both MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-
        // SHA256 are absent, the processing depends on the request being sent
        // over a reliable or an unreliable transport.
        if (resp.integrities.empty() ||
            std::any_of(resp.integrities.begin(), resp.integrities.end(),
                        [&req, &resp](const auto i) {
                            return !i.verify(req.hmac_key(), resp);
                        })) {
            // If the request was sent over an unreliable transport, the
            // response MUST be discarded, as if it had never been received.
            // This means that retransmits, if applicable, will continue.  If
            // all the responses received are discarded, then instead of
            // signaling a timeout after ending the transaction, the layer MUST
            // signal that the integrity protection was violated.
            ICE_IN_DEBUG { std::cout << "Integrity check failed\n"; }
            continue;
        }
        ret = true;
        break;
    }
END:
    from = trans.response_source;
    if (trans.is_linked())
        trans.unlink();
    trans.stop_retring();
    co_await retry_receiver.wait();
    co_return ret;
}

template <class NextLayer>
asioice::task<bool> datagram_client<NextLayer>::request_with_retry(
    stun::message &req, stun::message &resp, std::size_t retries) {
    asioice::endpoint resp_source;
    if (!this->_nonce.empty()) {
        // Once a request/response transaction has completed, the client will
        // have been presented a realm and nonce by the server and selected a
        // username and password with which it authenticated.  The client SHOULD
        // cache the username, password, realm, and nonce for subsequent
        // communications with the server.  When the client sends a subsequent
        // request, it MUST include either the USERNAME or USERHASH, REALM,
        // NONCE, and PASSWORD-ALGORITHM attributes with these cached values.
        // It MUST include a MESSAGE-INTEGRITY attribute or a MESSAGE-INTEGRITY-
        // SHA256 attribute, computed as described in Sections 14.5 and 14.6
        // using the cached password.  The choice between the two attributes
        // depends on the attribute received in the response to the first
        // request.
        req.nonce = this->_nonce;
        req.realm = this->_realm;
        if (this->_userhash)
            req.userhash = this->_userhash;
        else
            req.username = this->username();
        req.pwd_algorithm = this->_used_pwd_algo;
        req.integrities.emplace_back(this->_integrity);
        req.set_hmac_key(this->_hmac_key);
    }
    bool success = co_await this->request(req, resp_source, resp, retries);
    if (!success || resp_source != this->remote_endpoint())
        co_return false;
    if (resp.cls != stun::class_t::STUN_CLASS_RESP_ERROR &&
        resp.cls != stun::class_t::STUN_CLASS_RESP_SUCCESS)
        co_return false;
    if (resp.cls == stun::class_t::STUN_CLASS_RESP_SUCCESS)
        co_return true;
    assert(resp.error_code.has_value());
    const auto code = resp.error_code->code;
    if (code != 401 && code != 438) {
        ICE_IN_DEBUG {
            std::cerr << "Unexpected error code: " << code
                      << ", reason: " << resp.error_code->reason << "\n";
        }
        co_return false;
    }
    if (resp.nonce.empty()) {
        ICE_IN_DEBUG { std::cerr << "NONCE attribute not found\n"; }
        co_return false;
    }
    if (resp.nonce.starts_with(stun::STUN_NONCE_COOKIE) &&
        (resp.security_features() & 0x01) && resp.pwd_algorithms.empty()) {
        // If the response is an error response with an error code of 401
        // (Unauthenticated) or 438 (Stale Nonce), the client MUST test if the
        // NONCE attribute value starts with the "nonce cookie".  If so and the
        // "nonce cookie" has the STUN Security Feature "Password algorithms"
        // bit set to 1 but no PASSWORD-ALGORITHMS attribute is present, then
        // the client MUST NOT retry the request with a new transaction.
        co_return false;
    }
    if (code == 401) {
        if (resp.realm.empty()) {
            ICE_IN_DEBUG { std::cerr << "REALM attribute not found\n"; }
            co_return false;
        }
        req.fill_random_transaction_id();
        if (resp.nonce.starts_with(stun::STUN_NONCE_COOKIE) &&
            (resp.security_features() & 0x02)) {
            auto &userhash = req.userhash.emplace();
            stun::message::compute_userhash(userhash.data(), this->username(),
                                            resp.realm);
        } else {
            req.username = this->username();
        }
        req.realm = std::move(resp.realm);
        req.nonce = std::move(resp.nonce);
        if (!resp.pwd_algorithms.empty()) {
            std::ranges::sort(resp.pwd_algorithms,
                              [](const auto &a, const auto &b) noexcept {
                                  return a.algo() > b.algo();
                              });
            auto it = std::ranges::find_if(
                resp.pwd_algorithms,
                [](const auto &p) noexcept { return p.supported(); });
            if (it == resp.pwd_algorithms.end()) {
                // If the response contains a PASSWORD-ALGORITHMS attribute, and
                // this attribute does not contain any algorithm that is
                // supported by the client, then the client MUST NOT retry the
                // request with a new transaction.  The client MUST NOT perform
                // this retry if it is not changing the USERNAME, USERHASH,
                // REALM, or its associated password from the previous attempt.
                ICE_IN_DEBUG {
                    std::cout << "No supported password algorithms\n";
                }
                co_return false;
            }
            req.pwd_algorithm = *it;
            req.set_hmac_key(it->get_hmac_key(this->username(), req.realm,
                                              this->password()));
            req.pwd_algorithms = std::move(resp.pwd_algorithms);
        } else {
            // Use MD5 as default
            req.set_hmac_key(stun::message::password_algorithm{}.get_hmac_key(
                this->username(), req.realm, this->password()));
        }
        if (req.pwd_algorithms.empty())
            req.integrities.emplace_back(stun::message::integrity::SHA1);
        else
            req.integrities.emplace_back(stun::message::integrity::SHA256);
        req.use_fingerprint(true);

        // Send the second request
        success = co_await this->request(req, resp_source, resp, retries);
        if (!success || resp_source != this->remote_endpoint() ||
            resp.cls != stun::class_t::STUN_CLASS_RESP_SUCCESS ||
            resp.method != req.method || resp.integrities.empty()) {
            ICE_IN_DEBUG { std::cerr << "The second request failed\n"; }
            co_return false;
        }
        this->_nonce = std::move(req.nonce);
        this->_realm = std::move(req.realm);
        this->_hmac_key = req.hmac_key();
        this->_userhash = req.userhash;
        this->_used_pwd_algo = std::move(req.pwd_algorithm);
        this->_integrity = req.integrities.front();
        co_return true;
    }
    // Stale NONCE
    ICE_IN_DEBUG { std::cout << "Stale nonce, retrying...\n"; }
    req.nonce = std::move(resp.nonce);
    req.fill_random_transaction_id();
    success = co_await this->request(req, resp_source, resp, retries);
    if (!success || resp_source != this->remote_endpoint() ||
        resp.cls != stun::class_t::STUN_CLASS_RESP_SUCCESS ||
        resp.method != req.method || resp.integrities.empty()) {
        ICE_IN_DEBUG { std::cerr << "The second request failed\n"; }
        co_return false;
    }
    this->_nonce = std::move(req.nonce);
    co_return true;
}

template <class NextLayer> void datagram_client<NextLayer>::stop() noexcept {
    if (!_is_running)
        return;
    _is_running = false;

    // Send delete request without waiting response
    if (this->_relayed_address) {
        ICE_IN_DEBUG { std::cout << "Send delete allocation request\n"; }
        stun::message req;
        req.method = stun::method_t::STUN_METHOD_REFRESH;
        req.fill_random_transaction_id();
        req.lifetime = 0;
        req.use_fingerprint(true);
        req.nonce = this->_nonce;
        req.realm = this->_realm;
        if (this->_userhash)
            req.userhash = this->_userhash;
        else
            req.username = this->username();
        req.pwd_algorithm = this->_used_pwd_algo;
        req.integrities.emplace_back(this->_integrity);
        req.set_hmac_key(this->_hmac_key);

        auto buf = std::make_unique<std::byte[]>(1024);
        if (auto n = req.write_to(&buf[0], 1024); n > 0) {
            net::const_buffer data{&buf[0], (std::size_t)n};
            utils::detached_with_data(
                this->next_layer().async_send_to(data, this->_server,
                                                 utils::use_sender),
                this->shared_from_this(), std::move(buf));
        }
    }
    do_delete_allocation();
}

template <class NextLayer>
asioice::task<void> datagram_client<NextLayer>::refresh_allocation_task() {
    using Self = datagram_client<NextLayer>;
    if (!this->is_running())
        co_return;
    utils::scope_guard on_exit(
        [this]() noexcept { this->do_delete_allocation(); });
    typename Self::timer_type timer(this->get_executor());
    while (this->_lifetime > 0) {
        auto expire = std::chrono::seconds(this->_lifetime * 5 / 6);
        timer.expires_after(expire);
        co_await timer.async_wait(utils::use_sender);
        std::optional<bool> success =
            co_await (this->refresh(std::chrono::seconds(this->_lifetime)) |
                      stdexec::stopped_as_optional());
        if (!success || !*success) {
            ICE_IN_DEBUG { std::cerr << "Refresh task stopped\n"; }
            co_return;
        }
        ICE_IN_DEBUG {
            std::cout << "Refresh task succeeded, lifetime: " << this->_lifetime
                      << "\n";
        }
    }
}

template <class NextLayer>
void datagram_client<NextLayer>::start_refresh_allocation_task() {
    if (!this->is_running())
        return;
    utils::basic_scheduler<typename datagram_client<NextLayer>::executor_type>
        sched{this->get_executor()};
    utils::detached_with_data(
        stdexec::starts_on(
            sched,
            utils::stop_when(this->refresh_allocation_task(),
                             this->_stop_refresh_allocation_task.get_future() |
                                 stdexec::continues_on(sched))),
        this->shared_from_this());
}

template <class NextLayer>
asioice::task<std::optional<asioice::endpoint>>
datagram_client<NextLayer>::create_allocation(auto lifetime, auto... self) {
    if (!this->is_running())
        co_return std::nullopt;
    if (this->_relayed_address) {
        ICE_IN_DEBUG { std::cout << "WARN: Already allocated\n"; }
        co_return std::nullopt;
    }
    stun::message req;

    req.method = stun::method_t::STUN_METHOD_ALLOCATE;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.fill_random_transaction_id();
    req.requested_transport = true;
    req.lifetime =
        std::chrono::duration_cast<std::chrono::seconds>(lifetime).count();
    req.dont_fragment = true;
    req.use_fingerprint(true);

    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success)
        co_return std::nullopt;

    ICE_IN_DEBUG { std::cout << "Resp:\n" << resp.to_string() << '\n'; }
    if (!resp.lifetime || !resp.xor_relayed_address)
        co_return std::nullopt;
    this->_lifetime = *resp.lifetime;
    this->_relayed_address = resp.xor_relayed_address;
    this->_reflex_address = resp.xor_mapped_address;
    start_refresh_allocation_task();
    co_return this->_relayed_address;
}

template <class NextLayer>
asioice::task<bool> datagram_client<NextLayer>::refresh(auto time_to_expiry,
                                                        auto... self) {
    if (!this->is_running())
        co_return false;
    ICE_IN_DEBUG { std::cout << "Refreshing\n"; }
    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_REFRESH;
    req.fill_random_transaction_id();
    req.lifetime =
        std::chrono::duration_cast<std::chrono::seconds>(time_to_expiry)
            .count();
    req.use_fingerprint(true);

    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success || !resp.lifetime) {
        // TODO: Handle 437 error
        if (resp.error_code && resp.error_code->code == 437) {
            // If the client receives a 437 (Allocation Mismatch) error response
            // to its request to refresh the allocation, it should consider the
            // allocation no longer exists.
            this->do_delete_allocation();
        }
        co_return false;
    }
    if (*resp.lifetime == 0) {
        this->do_delete_allocation();
        co_return false;
    }
    this->_lifetime = *resp.lifetime;
    co_return true;
}

template <class NextLayer>
void datagram_client<NextLayer>::do_delete_allocation() {
    this->_lifetime = 0;
    this->_stop_refresh_allocation_task.set_value();
    this->_nonce.clear();
    this->_hmac_key.clear();
    this->_userhash.reset();
    this->_used_pwd_algo.reset();
    this->_integrity = stun::message::integrity::SHA1;
    this->_relayed_address.reset();
    this->_reflex_address.reset();
    while (!this->_permissions.empty()) {
        auto &perm = *this->_permissions.begin();
        perm.unlink();
        perm.stop();
    }
    this->_new_permissions_created.set_stopped();
    assert(this->_channel_to_peer.empty());
    assert(this->_peer_to_channel.empty());
    while (!this->_expired_channel.empty()) {
        auto &ch = *this->_expired_channel.begin();
        ch.stop();
    }
}

template <class NextLayer>
asioice::task<void>
datagram_client<NextLayer>::delete_allocation(auto... self) {
    if (!this->_relayed_address)
        co_return;
    stun::message req;
    req.method = stun::method_t::STUN_METHOD_REFRESH;
    req.fill_random_transaction_id();
    req.lifetime = 0;
    req.use_fingerprint(true);

    utils::scope_guard on_exit(
        [this]() noexcept { this->do_delete_allocation(); });
    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success)
        co_return;
    ICE_IN_DEBUG { std::cout << "TURN allocation deleted\n"; }
}

template <class NextLayer>
uint16_t datagram_client<NextLayer>::generate_channel_number() const {
    auto ch = std::max(this->_channel_to_peer.empty()
                           ? 0x3fff
                           : this->_channel_to_peer.rbegin()->channel(),
                       this->_expired_channel.empty()
                           ? 0
                           : this->_expired_channel.rbegin()->channel());
    ++ch;
    if (ch < 0x5000)
        return ch;
    uint16_t i = 0x4000;
    auto it1 = this->_channel_to_peer.begin();
    auto it2 = this->_expired_channel.begin();
    for (; it1 != this->_channel_to_peer.end() ||
           it2 != this->_expired_channel.end();) {
        uint16_t x = 0;
        if (it1 == this->_channel_to_peer.end())
            x = (it2++)->channel();
        else if (it2 == this->_expired_channel.end())
            x = (it1++)->channel();
        else {
            if (it1->channel() < it2->channel())
                x = (it1++)->channel();
            else
                x = (it2++)->channel();
        }
        if (x != i++)
            return i;
    }

    throw std::runtime_error("no available channel number");
}

template <class NextLayer>
asioice::task<void>
datagram_client<NextLayer>::permission_state::refresh_task() {
    utils::scope_guard on_exit([this]() noexcept {
        ICE_IN_DEBUG { std::cout << "permission_state::refresh_task exit\n"; }
        if (this->is_linked())
            this->unlink();
        while (!this->channels().empty()) {
            auto &channel = this->channels().front();
            this->channels().pop_front();
            channel.expire();
        }
    });
    typename datagram_client<NextLayer>::timer_type timer(
        this->client().get_executor());
    while (true) {
        timer.expires_after(std::chrono::seconds(60 * 4));
        auto ec = co_await timer.async_wait(utils::use_sender);
        if (ec)
            break;

        stun::message req, resp;
        req.cls = stun::class_t::STUN_CLASS_REQUEST;
        req.method = stun::method_t::STUN_METHOD_CREATE_PERMISSION;
        req.use_fingerprint(true);
        req.fill_random_transaction_id();
        req.xor_peer_address.emplace_back(this->ip(), 0);

        if (co_await this->client().request_with_retry(req, resp, 7)) {
            ICE_IN_DEBUG {
                std::cout
                    << "permission_state::refresh_task: refreshed permission \""
                    << this->ip() << "\"\n";
            }
        } else {
            ICE_IN_DEBUG {
                std::cout << "permission_state::refresh_task: failed to "
                             "refresh permission \""
                          << this->ip() << "\"\n";
            }
            break;
        }
    }
}

template <class NextLayer>
void datagram_client<NextLayer>::permission_state::start() {
    if (!this->_client->is_running())
        return;
    utils::basic_scheduler<typename datagram_client<NextLayer>::executor_type>
        sched{this->client().get_executor()};
    utils::detached_with_data(
        stdexec::starts_on(sched,
                           utils::stop_when(this->refresh_task(),
                                            this->_stop.get_future() |
                                                stdexec::continues_on(sched))),
        this->shared_from_this());
}

template <class NextLayer>
asioice::task<bool>
datagram_client<NextLayer>::create_permission(std::ranges::view auto peers,
                                              auto... self) {
    if (!this->is_running() || peers.empty() || !this->_relayed_address)
        co_return false;
    if (this->_relayed_address->address().is_v4() &&
        std::ranges::any_of(
            peers, [](const auto &peer) noexcept { return !peer.is_v4(); }))
        co_return false;
    if (this->_relayed_address->address().is_v6() &&
        std::ranges::any_of(
            peers, [](const auto &peer) noexcept { return !peer.is_v6(); }))
        co_return false;
    ICE_IN_DEBUG { std::cout << "Creating or refreshing permissions\n"; }
    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_CREATE_PERMISSION;
    req.use_fingerprint(true);

    asioice::small_set<net::ip::address> creating;
    for (const auto &peer : peers) {
        if (this->_permissions.find(peer) != this->_permissions.end())
            continue;
        auto it = this->_creating_permissions.find(peer);
        if (it == this->_creating_permissions.end())
            req.xor_peer_address.emplace_back(peer, 0);
        else
            creating.insert(peer);
    }

    auto wait_finish =
        stdexec::just() | stdexec::let_value([&] {
            return this->_new_permissions_created.get_future() |
                   stdexec::continues_on(
                       utils::basic_scheduler<
                           typename datagram_client<NextLayer>::executor_type>{
                           this->get_executor()});
        }) |
        stdexec::then([&] {
            return std::ranges::all_of(creating, [&](const auto &ip) {
                return this->_creating_permissions.find(ip) ==
                       this->_creating_permissions.end();
            });
        }) |
        exec::repeat_until() | stdexec::then([&] {
            return std::ranges::all_of(creating, [&](const auto &ip) {
                return this->_permissions.find(ip) != this->_permissions.end();
            });
        });
    if (req.xor_peer_address.empty()) {
        if (creating.empty())
            co_return true;
        co_return co_await std::move(wait_finish);
    }
    std::ranges::sort(req.xor_peer_address,
                      [](const auto &a, const auto &b) noexcept {
                          return a.address() < b.address();
                      });
    {
        const auto [first, last] = std::ranges::unique(
            req.xor_peer_address, [](const auto &a, const auto &b) noexcept {
                return a.address() == b.address();
            });
        req.xor_peer_address.erase(first, last);
    }
    utils::scope_guard clear_creating([&]() noexcept {
        for (const auto &addr : req.xor_peer_address)
            this->_creating_permissions.erase(addr.address());
        this->_new_permissions_created.set_value();
    });
    for (const auto &addr : req.xor_peer_address)
        this->_creating_permissions.insert(addr.address());
    req.fill_random_transaction_id();

    stun::message resp;
    bool success = false;
    if (creating.empty())
        success = co_await this->request_with_retry(req, resp, 7);
    else {
        std::tuple<std::tuple<bool>, std::tuple<bool>> result =
            co_await stdexec::when_all(std::move(wait_finish),
                                       this->request_with_retry(req, resp, 7));
        success = std::get<0>(std::get<0>(result)) &&
                  std::get<0>(std::get<1>(result));
    }
    if (!success) {
        ICE_IN_DEBUG { std::cout << "Create or refresh permissions failed\n"; }
        co_return false;
    }
    ICE_IN_DEBUG { std::cout << "Create or refresh permissions success\n"; }
    if (!this->_is_running)
        co_return true;
    for (const auto &peer : req.xor_peer_address) {
        ICE_IN_DEBUG {
            assert(this->_permissions.find(peer.address()) ==
                   this->_permissions.end());
        }
        auto state =
            std::make_shared<datagram_client<NextLayer>::permission_state>(
                this->shared_from_this(), peer.address());
        state->start();
        this->_permissions.insert(*state);
    }
    co_return true;
}

template <class NextLayer>
void datagram_client<NextLayer>::delete_permission(
    const net::ip::address &peer) noexcept {
    if (!this->is_running())
        return;
    ICE_IN_DEBUG { std::cout << "Delete permission of \"" << peer << "\"\n"; }
    auto it = this->_permissions.find(peer);
    if (it == this->_permissions.end())
        return;
    it->unlink();
    it->stop();
}

template <class NextLayer>
template <class ConstBufferSequence>
asioice::task<std::tuple<std::error_code, std::size_t>>
datagram_client<NextLayer>::async_send_to(ConstBufferSequence buffer_sequence,
                                          net::ip::udp::endpoint destination,
                                          auto... self) {
    if (!this->is_running())
        co_return std::make_tuple(
            std::make_error_code(std::errc::operation_canceled), 0);

    asioice::buffer_wrapper buffers{buffer_sequence};
    auto it = this->_peer_to_channel.find(destination);
    if (it != this->_peer_to_channel.end()) {
        ICE_IN_DEBUG { std::cout << "Sending channel data\n"; }
        co_return co_await this->send_channel_data(std::move(buffers),
                                                   it->channel());
    }
    auto permission = this->_permissions.find(destination.address());
    if (permission == this->_permissions.end()) {
        ICE_IN_DEBUG {
            std::cout << "No permission of " << destination.address() << "\n";
        }
        co_return std::make_tuple(std::make_error_code(std::errc::bad_address),
                                  0);
    }
    // send indication
    ICE_IN_DEBUG { std::cout << "Sending indication\n"; }
    std::size_t data_size = net::buffer_size(buffers.buffers());

    stun::message msg;
    msg.cls = stun::class_t::STUN_CLASS_INDICATION;
    msg.method = stun::method_t::STUN_METHOD_SEND;
    msg.fill_random_transaction_id();
    msg.reserve_turn_data(data_size);
    msg.xor_peer_address.emplace_back(destination.address(),
                                      destination.port());

    char buf[20 + 4 + 20 + 4] = {};
    int n = msg.write_to(buf, sizeof(buf));
    assert(n <= sizeof(buf) && "Write turn send indication failed");

    buffers.buffers().insert(buffers.buffers().begin(),
                             net::const_buffer(buf, n));
    char pad[4] = {0};
    if (data_size % 4 != 0) {
        buffers.buffers().emplace_back(pad, 4 - data_size % 4);
    }
    co_return co_await this->next_layer().async_send_to(
        buffers.buffers(), this->_server, utils::use_sender);
}

template <class NextLayer>
template <class ConstBufferSequence>
auto datagram_client<NextLayer>::send_channel_data(
    ConstBufferSequence buffer_sequence, uint16_t channel, auto... self) {
    asioice::buffer_wrapper buffers{buffer_sequence};
    auto data_size = net::buffer_size(buffers.buffers());
    return stdexec::just(std::move(buffers), std::array<char, 4>{},
                         std::move(self)...) |
           stdexec::let_value(
               [this, channel, data_size](auto &buffers, auto &header,
                                          const auto &...self) noexcept {
                   binary::write_big<uint16_t>(header.data(), channel);
                   binary::write_big<uint16_t>(header.data() + 2,
                                               (uint16_t)data_size);
                   buffers.buffers().insert(
                       buffers.buffers().begin(),
                       net::const_buffer(header.data(), header.size()));
                   return this->next_layer().async_send_to(
                       buffers.buffers(), this->_server, utils::use_sender);
               });
}

template <class NextLayer>
asioice::task<bool>
datagram_client<NextLayer>::channel_bind(net::ip::udp::endpoint peer,
                                         auto... self) {
    if (!this->is_running())
        co_return false;
    if (!this->_relayed_address) {
        ICE_IN_DEBUG { std::cout << "Haven't allocate.\n"; }
        co_return false;
    }
    if ((this->_relayed_address->address().is_v4() &&
         !peer.address().is_v4()) ||
        (this->_relayed_address->address().is_v6() &&
         !peer.address().is_v6())) {
        ICE_IN_DEBUG {
            std::cout << "Peer address is not the same type as the relayed "
                         "address.\n";
        }
        co_return false;
    }
    uint16_t channel = 0;
    if (auto it = this->_peer_to_channel.find(peer);
        it != this->_peer_to_channel.end()) {
        // refresh
        channel = it->channel();
    } else
        channel = this->generate_channel_number();
    ICE_IN_DEBUG {
        std::cout << "Binding or refreshing channel: {" << peer.address() << ":"
                  << peer.port() << ", " << channel << "}\n";
    }
    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_CHANNEL_BIND;
    req.fill_random_transaction_id();
    req.use_fingerprint(true);
    req.xor_peer_address.emplace_back(peer.address(), peer.port());
    req.channel_number = channel;

    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success) {
        ICE_IN_DEBUG {
            std::cout << "Bind or refresh channel failed: {" << peer.address()
                      << ":" << peer.port() << ", " << channel << "}\n";
        }
        co_return false;
    }
    ICE_IN_DEBUG {
        std::cout << "Bind or refresh channel success: {" << peer.address()
                  << ":" << peer.port() << ", " << channel << "}\n";
    }
    if (!this->is_running())
        co_return true;
    auto ch = this->_channel_to_peer.find(channel);
    if (ch == this->_channel_to_peer.end()) {
        auto c = std::make_shared<datagram_client<NextLayer>::channel_state>(
            this->shared_from_this(), channel, peer);
        c->start();
        this->_channel_to_peer.insert(*c);
        this->_peer_to_channel.insert(*c);
        ch = this->_channel_to_peer.iterator_to(*c);
    } else {
        // TODO: update lifetime
        co_return true;
    }
    utils::scope_guard on_error([&]() noexcept {
        auto &c = *ch;
        this->_channel_to_peer.erase(ch);
        this->_peer_to_channel.erase(this->_peer_to_channel.iterator_to(c));
        c.stop();
    });
    auto permission = this->_permissions.find(peer.address());
    if (permission == this->_permissions.end()) {
        auto p = std::make_shared<datagram_client<NextLayer>::permission_state>(
            this->shared_from_this(), peer.address());
        p->start();
        this->_permissions.insert(*p);
        permission = this->_permissions.iterator_to(*p);
    }
    permission->channels().push_back(*ch);
    ch->set_permission(permission->shared_from_this());
    on_error.dismiss();
    // TODO: Update state
    co_return true;
}

template <class NextLayer>
void datagram_client<NextLayer>::channel_state::start() {
    if (!this->_client->is_running())
        return;
    utils::basic_scheduler<typename datagram_client<NextLayer>::executor_type>
        sched{this->client().get_executor()};
    utils::detached_with_data(
        stdexec::starts_on(sched,
                           utils::stop_when(this->refresh_task(),
                                            this->_stop.get_future() |
                                                stdexec::continues_on(sched))),
        this->shared_from_this());
}

template <class NextLayer>
asioice::task<void> datagram_client<NextLayer>::channel_state::refresh_task() {
    utils::scope_guard on_error([this]() noexcept {
        ICE_IN_DEBUG {
            std::cout << "refresh_task stopped, channel: " << this->channel()
                      << ", peer: " << this->peer().address() << ':'
                      << this->peer().port() << '\n';
        }
        this->remove_from_set();
        this->remove_from_permission();
    });
    typename datagram_client<NextLayer>::timer_type timer(
        this->client().get_executor());
    while (true) {
        timer.expires_after(std::chrono::seconds(60 * 9));
        auto ec = co_await timer.async_wait(utils::use_sender);
        if (ec)
            break;
        std::optional<bool> ret = co_await stdexec::stopped_as_optional(
            this->client().channel_bind(this->peer()));
        if (!ret) {
            ICE_IN_DEBUG {
                std::cout << "channel_state::refresh_task cancelled, channel = "
                          << this->channel() << '\n';
            }
            break;
        }
        if (!*ret) {
            ICE_IN_DEBUG {
                std::cout << "channel_state::refresh_task failed, channel = "
                          << this->channel() << '\n';
            }
            break;
        }
    }
    if (this->_state !=
        datagram_client<NextLayer>::channel_state::state_t::expired)
        co_return;
    on_error.dismiss();
    /*
        To prevent race conditions, the client MUST wait 5 minutes after the
       channel binding expires before attempting to bind the channel number to a
       different transport address or the transport address to a different
       channel number.
    */
    ICE_IN_DEBUG {
        std::cout << "refresh_task expired, channel: " << this->channel()
                  << ", peer: " << this->peer().address() << ':'
                  << this->peer().port() << '\n';
    }
    this->set_permission(nullptr);
    utils::scope_guard on_exit([this]() noexcept { this->remove_from_set(); });
    timer.expires_after(std::chrono::seconds(60 * 5));
    co_await utils::stop_when(timer.async_wait(utils::use_sender),
                              this->_stop.get_future());
}

inline bool validate_turn_channel(const asioice::io_buffer_ptr &buf,
                                  uint16_t &channel_number,
                                  uint16_t &len) noexcept {
    if (buf->size() < 4) {
        ICE_IN_DEBUG { std::cout << "WARNING: invalid turn channel message\n"; }
        return false;
    }
    channel_number = binary::read_big<uint16_t>(buf->data());
    len = binary::read_big<uint16_t>(buf->begin() + 2);
    if (channel_number < 0x4000 || channel_number > 0x4FFF) {
        ICE_IN_DEBUG { std::cout << "WARNING: invalid turn channel number\n"; }
        return false;
    }
    if (buf->size() == len + 4)
        return true;
    if (len & 3) {
        auto pad = 4 - (len & 3);
        if (buf->size() == len + 4 + pad)
            return true;
        ICE_IN_DEBUG { std::cout << "WARNING: invalid turn channel message\n"; }
        return false;
    }
    return true;
}

template <class NextLayer>
bool datagram_client<NextLayer>::datagram_received(
    io_buffer_ptr &buffer, const asioice::endpoint &endpoint) {
    if (!buffer || buffer->size() < 4 || endpoint != this->_server)
        return false;
    uint8_t first_byte = *buffer->begin();
    if (first_byte >= 64 && first_byte <= 79) {
        // TURN channel
        uint16_t ch, len;
        if (!validate_turn_channel(buffer, ch, len)) {
            // ignore
            return true;
        }
        auto it = this->_channel_to_peer.find(ch);
        if (it == this->_channel_to_peer.end()) {
            ICE_IN_DEBUG {
                std::cout << "WARNING: unknown channel: " << ch << '\n';
            }
            // ignore
            return true;
        }
        buffer->consume_front(4);
        buffer->consume_back(buffer->size() - len);
        assert(buffer->size() == len);
        dispatch_receivers(this->receivers(), buffer, it->peer());
        return true;
    } else if (first_byte <= 3) {
        // STUN message
        if (buffer->size() < asioice::stun::HEADER_SIZE) {
            // ignore
            return true;
        }
        auto cls =
            asioice::stun::message::get_class(buffer->data(), buffer->size());
        if (cls == stun::class_t::STUN_CLASS_RESP_SUCCESS ||
            cls == stun::class_t::STUN_CLASS_RESP_ERROR) {
            dispatch_stun_response(this->_transactions, endpoint,
                                   buffer->data(), buffer->size(), nullptr);
            return true;
        }
        if (cls == stun::class_t::STUN_CLASS_REQUEST) {
            // STUN request, ignore
            return true;
        }
        stun::message indication;
        if (!indication.parse(buffer->data(), buffer->size()) ||
            indication.method != stun::method_t::STUN_METHOD_DATA ||
            indication.xor_peer_address.size() != 1 ||
            !indication.has_turn_data()) {
            ICE_IN_DEBUG { std::cout << "WARNING: invalid STUN indication\n"; }
            return true;
        }
        const std::byte *turn_data = indication.turn_data();
        std::size_t turn_data_len = indication.turn_data_size();
        buffer->consume_front((const uint8_t *)turn_data - buffer->begin());
        buffer->consume_back(buffer->size() - turn_data_len);
        assert(buffer->size() == turn_data_len);
        dispatch_receivers(this->receivers(), buffer,
                           indication.xor_peer_address.front());
        return true;
    }
    // ignore
    return true;
}

} // namespace asioice::turn::impl