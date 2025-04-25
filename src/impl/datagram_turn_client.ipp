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
ice::task<void> datagram_client<NextLayer>::refresh_allocation_task(auto self) {
    net::steady_timer timer(this->context());
    while (this->_lifetime > 0) {
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
    }
}

template <class NextLayer>
void datagram_client<NextLayer>::start_refresh_allocation_task() {
    this->_stop_refresh_allocation_task.set_value(); // Cancel previous task
    asio2exec::scheduler sched{this->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched, utils::stop_when(
                   this->refresh_allocation_task(this->shared_from_this()),
                   this->_stop_refresh_allocation_task.get_future() |
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
    start_refresh_allocation_task();
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
    this->clear_permissions();
}

template <class NextLayer>
ice::task<void> datagram_client<NextLayer>::delete_allocation(auto... self) {
    stun::message req;
    req.method = stun::method_t::STUN_METHOD_REFRESH;
    req.fill_random_transaction_id();
    req.lifetime = 0;
    req.use_fingerprint(true);

    utils::scope_guard g([this]() noexcept { this->do_delete_allocation(); });
    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success)
        co_return;
    ICE_IN_DEBUG { std::cout << "TURN allocation deleted\n"; }
}

template <class NextLayer>
void datagram_client<NextLayer>::permission_state::start() {
    asio2exec::scheduler sched{this->client->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched, utils::stop_when(
                   this->refresh_permission_task(this->shared_from_this()),
                   this->_stop.get_future() | stdexec::continues_on(sched))));
}

template <class NextLayer>
datagram_client<NextLayer>::permission_state::~permission_state() {
    if (!this->client)
        return;
    auto &c = *this->client;
    c._ip_to_channel.erase(this->peer_ip);
    for (const auto [channel, _] : this->channel_to_port) {
        c._channel_to_ip.erase(channel);
    }
    this->client->mark_channel_number_expired(
        std::views::keys(this->channel_to_port));
}

template <class NextLayer>
ice::task<void>
datagram_client<NextLayer>::permission_state::refresh_permission_task(
    auto self) {
    net::steady_timer timer{self->client->context()};
    while (true) {
        timer.expires_after(std::chrono::seconds(60 * 4));
        auto ret = co_await (timer.async_wait(asio2exec::use_sender) |
                             stdexec::stopped_as_optional());
        if (!ret) {
            ICE_IN_DEBUG {
                std::cout << "Permission of " << this->peer_ip.to_string()
                          << " expired.\n";
            }
            co_return;
        }
        bool refreshed =
            co_await this->client->create_permission(this->peer_ip);
        if (!refreshed) {
            ICE_IN_DEBUG {
                std::cout << "Permission of " << this->peer_ip.to_string()
                          << " refresh failed.\n";
            }
            co_return;
        }
    }
}

template <class NextLayer>
void datagram_client<NextLayer>::clear_permissions() noexcept {
    for (const auto &[_, permission] : this->_ip_to_channel) {
        permission->stop();
    }
}

template <class NextLayer>
uint16_t datagram_client<NextLayer>::generate_channel_number() const noexcept {
    return std::max(this->_channel_to_ip.rbegin()->first,
                    this->_expired_number.empty()
                        ? 0
                        : std::ranges::max_element(
                              this->_expired_number,
                              [](const auto &a, const auto &b) noexcept {
                                  return a.channel_number < b.channel_number;
                              })
                              ->channel_number) +
           1;
}

template <class NextLayer>
void datagram_client<NextLayer>::mark_channel_number_expired(
    std::ranges::view auto channel_numbers) {
    if (channel_numbers.empty() || !this->_is_running)
        return;
    auto now = std::chrono::steady_clock::now();
    for (auto x : channel_numbers) {
        this->_expired_number.emplace_back(x,
                                           now + std::chrono::seconds(60 * 5));
    }
    this->start_expire_channel_number_task();
}

template <class NextLayer>
ice::task<void>
datagram_client<NextLayer>::expire_channel_number_task(auto self) {
    net::steady_timer timer{this->context()};
    while (true) {
        auto now = std::chrono::steady_clock::now();
        auto it = std::lower_bound(this->_expired_number.begin(),
                                   this->_expired_number.end(),
                                   expired_channel_number{0, now});
        if (it == this->_expired_number.end()) {
            this->_expired_number.clear();
            co_return;
        } else if (it->expiry_time == now) {
            this->_expired_number.erase(this->_expired_number.begin(), it + 1);
        } else {
            this->_expired_number.erase(this->_expired_number.begin(), it);
        }
        if (this->_expired_number.empty())
            co_return;
        timer.expires_at(this->_expired_number.front().expiry_time);
        co_await timer.async_wait(asio2exec::use_sender);
    }
}

template <class NextLayer>
void datagram_client<NextLayer>::start_expire_channel_number_task() {
    if (this->_expired_number.size() != 1 || !this->_is_running)
        return;
    asio2exec::scheduler sched{this->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched, utils::stop_when(
                   this->expire_channel_number_task(this->shared_from_this()),
                   this->_stop_expire_number_task.get_future())));
}

template <class NextLayer>
ice::task<bool>
datagram_client<NextLayer>::create_permission(std::ranges::view auto peers,
                                              auto... self) {
    if (!this->_is_running || peers.empty() || !this->_relayed_address)
        co_return false;
    if (this->_relayed_address->address.is_v4() &&
        std::ranges::any_of(
            peers, [](const auto &peer) noexcept { return !peer.is_v4(); }))
        co_return false;
    if (this->_relayed_address->address.is_v6() &&
        std::ranges::any_of(
            peers, [](const auto &peer) noexcept { return !peer.is_v6(); }))
        co_return false;
    ICE_IN_DEBUG { std::cout << "Create permissions\n"; }
    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_CREATE_PERMISSION;
    req.use_fingerprint(true);
    for (const auto &peer : peers)
        req.xor_peer_address.emplace_back(peer, 0);
    std::ranges::sort(req.xor_peer_address,
                      [](const auto &a, const auto &b) noexcept {
                          return a.address < b.address;
                      });
    {
        const auto [first, last] = std::ranges::unique(
            req.xor_peer_address, [](const auto &a, const auto &b) noexcept {
                return a.address == b.address;
            });
        req.xor_peer_address.erase(first, last);
    }
    req.fill_random_transaction_id();

    stun::message resp;
    bool success = co_await this->request_with_retry(req, resp, 7);
    if (!success) {
        ICE_IN_DEBUG { std::cout << "Create or refresh permissions failed\n"; }
        co_return false;
    }
    ICE_IN_DEBUG { std::cout << "Create or refresh permissions success\n"; }
    for (const auto &peer : req.xor_peer_address) {
        if (this->_ip_to_channel.contains(peer.address))
            continue;
        auto ptr =
            std::make_shared<datagram_client<NextLayer>::permission_state>();
        ptr->peer_ip = peer.address;
        ptr->client = this->shared_from_this();
        this->_ip_to_channel.emplace(peer.address, ptr.get());
        ptr->start();
    }
    co_return true;
}

template <class NextLayer>
void datagram_client<NextLayer>::delete_permission(
    const net::ip::address &peer) {
    ICE_IN_DEBUG { std::cout << "Delete permissions\n"; }
    auto it = this->_ip_to_channel.find(peer);
    if (it == this->_ip_to_channel.end())
        return;
    it->second->stop();
}

} // namespace ice::turn::impl