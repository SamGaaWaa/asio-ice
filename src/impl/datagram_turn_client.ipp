namespace ice::turn::impl {

template <class NextLayer>
ice::task<bool> datagram_client<NextLayer>::request_with_retry(
    stun::message &req, stun::message &resp, std::size_t retries) {
    typename datagram_client<NextLayer>::endpoint_type resp_from;
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
    bool success = co_await this->request(req, resp_from, resp, retries);
    if (!success || resp_from != this->remote_endpoint())
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
        success = co_await this->request(req, resp_from, resp, retries);
        if (!success || resp_from != this->remote_endpoint() ||
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
    success = co_await this->request(req, resp_from, resp, retries);
    if (!success || resp_from != this->remote_endpoint() ||
        resp.cls != stun::class_t::STUN_CLASS_RESP_SUCCESS ||
        resp.method != req.method || resp.integrities.empty()) {
        ICE_IN_DEBUG { std::cerr << "The second request failed\n"; }
        co_return false;
    }
    this->_nonce = std::move(req.nonce);
    co_return true;
}

template <class NextLayer>
ice::task<void> datagram_client<NextLayer>::refresh_task(auto self) {
    net::steady_timer timer(this->context());
    while (true) {
        auto expire = std::chrono::seconds(this->_lifetime * 5 / 6);
        timer.expires_after(expire);
        co_await timer.async_wait(asio2exec::use_sender);
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
        if (this->_lifetime == 0)
            co_return;
    }
}

template <class NextLayer>
void datagram_client<NextLayer>::start_refresh_task() {
    this->_stop_refresh_task.set_value(); // Cancel previous task
    asio2exec::scheduler sched{this->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched, utils::stop_when(this->refresh_task(this->shared_from_this()),
                                this->_stop_refresh_task.get_future() |
                                    stdexec::continues_on(sched))));
}

template <class NextLayer>
ice::task<std::optional<net::ip::udp::endpoint>>
datagram_client<NextLayer>::create_allocation(auto lifetime, auto... self) {
    if (this->_relayed_address) {
        ICE_IN_DEBUG { std::cout << "WARN: Already allocated\n"; }
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
    start_refresh_task();
    co_return net::ip::udp::endpoint{this->_relayed_address->address,
                                     this->_relayed_address->port};
}

template <class NextLayer>
ice::task<bool> datagram_client<NextLayer>::refresh(auto time_to_expiry,
                                                    auto... self) {
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
    if (!success || !resp.lifetime) // TODO: Handle 437 error
        co_return false;
    this->_lifetime = *resp.lifetime;
    co_return true;
}

template <class NextLayer>
ice::task<void> datagram_client<NextLayer>::delete_allocation(auto... self) {
    stun::message req;
    req.method = stun::method_t::STUN_METHOD_REFRESH;
    req.fill_random_transaction_id();
    req.lifetime = 0;
    req.use_fingerprint(true);

    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success)
        co_return;
    ICE_IN_DEBUG { std::cout << "TURN allocation deleted\n"; }
    this->_stop_refresh_task.set_value();
    this->_nonce.clear();
    this->_hmac_key.clear();
    this->_userhash.reset();
    this->_used_pwd_algo.reset();
    this->_integrity.reset();
    this->_lifetime = 0;
    this->_relayed_address.reset();
    this->_reflex_address.reset();
}

} // namespace ice::turn::impl