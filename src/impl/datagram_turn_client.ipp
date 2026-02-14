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
    utils::detached_with_data(stdexec::starts_on(
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
    asio2exec::scheduler sched{this->_client->context()};
    utils::detached_with_data(stdexec::starts_on(
        sched, utils::stop_when(
                   this->refresh_permission_task(this->shared_from_this()),
                   this->_stop.get_future() | stdexec::continues_on(sched))));
}

template <class NextLayer>
datagram_client<NextLayer>::permission_state::~permission_state() {
    if (!this->_client)
        return;
    auto &c = *this->_client;
    c._ip_to_channel.erase(this->ip());
    this->remove_all_channels();
}

template <class NextLayer>
std::optional<uint16_t>
datagram_client<NextLayer>::permission_state::find_channel_by_port(
    uint16_t port) const noexcept {
    auto it = this->_port_to_channel.find(port);
    if (it == this->_port_to_channel.end())
        return std::nullopt;
    return it->second;
}

template <class NextLayer>
std::optional<uint16_t>
datagram_client<NextLayer>::permission_state::find_port_by_channel(
    uint16_t channel) const noexcept {
    auto it = this->_channel_to_port.find(channel);
    if (it == this->_channel_to_port.end())
        return std::nullopt;
    return it->second;
}

template <class NextLayer>
bool datagram_client<NextLayer>::permission_state::add_channel(
    uint16_t port, uint16_t channel) noexcept {
    auto [it, success] = this->_port_to_channel.insert({port, channel});
    if (!success)
        return false;
    this->_channel_to_port.insert({channel, port});
    this->_client->_channel_to_ip[channel] = this;
    auto now = std::chrono::steady_clock::now();
    this->add_to_refresh_queue(channel, now + std::chrono::seconds(60 * 9));
    return true;
}

template <class NextLayer>
bool datagram_client<NextLayer>::permission_state::remove_channel(
    uint16_t channel) noexcept {
    auto it = this->_channel_to_port.find(channel);
    if (it == this->_channel_to_port.end())
        return false;
    this->_client->_channel_to_ip.erase(channel);
    this->_client->mark_channel_number_expired(std::views::single(it->second));
    this->_port_to_channel.erase(it->second);
    this->_channel_to_port.erase(it);
    this->remove_from_refresh_queue(channel);
    return true;
}

template <class NextLayer>
void datagram_client<
    NextLayer>::permission_state::remove_all_channels() noexcept {
    if (this->_channel_to_port.empty())
        return;
    auto &c = *this->_client;
    for (const auto [channel, _] : this->_channel_to_port) {
        c._channel_to_ip.erase(channel);
    }
    c.mark_channel_number_expired(std::views::keys(this->_channel_to_port));
    this->_port_to_channel.clear();
    this->_channel_to_port.clear();
    this->_refresh_queue.clear();
}

template <class NextLayer>
auto datagram_client<NextLayer>::permission_state::all_channels()
    const noexcept {
    return std::views::keys(this->_channel_to_port);
}

template <class NextLayer>
auto datagram_client<NextLayer>::permission_state::all_ports() const noexcept {
    return std::views::keys(this->_port_to_channel);
}

template <class NextLayer>
void datagram_client<NextLayer>::permission_state::add_to_refresh_queue(
    uint16_t channel, std::chrono::steady_clock::time_point refresh_time) {
    this->_refresh_queue.emplace_back(channel, refresh_time);
    std::ranges::push_heap(
        this->_refresh_queue,
        [](const auto &a, const auto &b) { return a.second > b.second; });
}

template <class NextLayer>
std::pair<uint16_t, std::chrono::steady_clock::time_point>
datagram_client<NextLayer>::permission_state::next_refresh_channel() noexcept {
    auto res = this->_refresh_queue.front();
    std::ranges::pop_heap(
        this->_refresh_queue,
        [](const auto &a, const auto &b) { return a.second > b.second; });
    this->_refresh_queue.pop_back();
    return res;
}

template <class NextLayer>
void datagram_client<NextLayer>::permission_state::remove_from_refresh_queue(
    uint16_t channel) noexcept {
    auto it =
        std::ranges::find_if(this->_refresh_queue, [channel](const auto &a) {
            return a.first == channel;
        });
    if (it == this->_refresh_queue.end())
        return;
    this->_refresh_queue.erase(it);
    std::ranges::make_heap(
        this->_refresh_queue,
        [](const auto &a, const auto &b) { return a.second > b.second; });
}

template <class NextLayer>
ice::task<void>
datagram_client<NextLayer>::permission_state::refresh_permission_task(
    auto self) {
    net::steady_timer timer{self->_client->context()};
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (this->_refresh_queue.empty() ||
            (this->_refresh_queue.front().second > now &&
             this->_refresh_queue.front().second - now >
                 std::chrono::seconds(60 * 4))) {
            timer.expires_at(now + std::chrono::seconds(60 * 4));
            auto ret = co_await (timer.async_wait(asio2exec::use_sender) |
                                 stdexec::stopped_as_optional());
            if (!ret) {
                ICE_IN_DEBUG { std::cout << "Refresh task cancelled\n"; }
                co_return;
            }
            if (!co_await this->_client->create_permission(this->ip())) {
                ICE_IN_DEBUG { std::cout << "Failed to refresh permission\n"; }
                co_return;
            }
            continue;
        }
        auto next = this->next_refresh_channel();
        net::ip::udp::endpoint peer(
            this->ip(), this->find_port_by_channel(next.first).value());
        if (next.second <= now) {
            utils::scope_guard guard([&]() noexcept {
                this->add_to_refresh_queue(next.first,
                                           now + std::chrono::seconds(60 * 9));
            });
            bool success =
                co_await this->_client->channel_bind(peer, next.first);
            if (!success) {
                ICE_IN_DEBUG { std::cerr << "Refresh channel failed\n"; }
                this->remove_channel(next.first);
                continue;
            }
            ICE_IN_DEBUG {
                std::cout << "Refresh channel " << next.first << " success\n";
            }
            continue;
        }
        timer.expires_at(next.second);
        auto ret = co_await (timer.async_wait(asio2exec::use_sender) |
                             stdexec::stopped_as_optional());
        if (!ret) {
            ICE_IN_DEBUG { std::cout << "Refresh task cancelled\n"; }
            co_return;
        }
        utils::scope_guard guard([&]() noexcept {
            this->add_to_refresh_queue(
                next.first, next.second + std::chrono::seconds(60 * 9));
        });
        bool success = co_await this->_client->channel_bind(peer, next.first);
        if (!success) {
            ICE_IN_DEBUG { std::cerr << "Refresh channel failed\n"; }
            this->remove_channel(next.first);
            continue;
        }
        ICE_IN_DEBUG {
            std::cout << "Refresh channel " << next.first << " success\n";
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
uint16_t datagram_client<NextLayer>::generate_channel_number() const {
    auto ch = std::max(this->_channel_to_ip.empty()
                           ? 0x3fff
                           : this->_channel_to_ip.rbegin()->first,
                       this->_expired_number.empty()
                           ? 0
                           : std::ranges::max_element(
                                 this->_expired_number,
                                 [](const auto &a, const auto &b) noexcept {
                                     return a.channel_number < b.channel_number;
                                 })
                                 ->channel_number) +
              1;
    if (ch < 0x5000)
        return ch;
    std::vector<uint16_t> used;
    used.resize(this->_channel_to_ip.size() + this->_expired_number.size());
    std::ranges::copy(this->_channel_to_ip | std::views::keys, used.begin());
    std::ranges::transform(
        this->_expired_number, used.begin() + this->_channel_to_ip.size(),
        [](const auto &a) noexcept { return a.channel_number; });
    std::ranges::sort(used);
    uint16_t i = 0x4000;
    for (auto &ch : used) {
        if (ch != i)
            return i;
        ++i;
    }
    throw std::runtime_error("no available channel number");
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
    utils::detached_with_data(stdexec::starts_on(
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
    if (this->_relayed_address->address().is_v4() &&
        std::ranges::any_of(
            peers, [](const auto &peer) noexcept { return !peer.is_v4(); }))
        co_return false;
    if (this->_relayed_address->address().is_v6() &&
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
                          return a.address() < b.address();
                      });
    {
        const auto [first, last] = std::ranges::unique(
            req.xor_peer_address, [](const auto &a, const auto &b) noexcept {
                return a.address() == b.address();
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
        std::make_shared<datagram_client<NextLayer>::permission_state>(
            peer.address, *this)
            ->start();
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

template <class NextLayer>
template <class ConstBufferSequence>
ice::task<std::tuple<std::error_code, std::size_t>>
datagram_client<NextLayer>::async_send_to(
    const ConstBufferSequence &buffers,
    const typename datagram_client<NextLayer>::endpoint_type &destination,
    auto... self) {
    auto it = this->_ip_to_channel.find(destination.address());
    if (it == this->_ip_to_channel.end()) {
        ICE_IN_DEBUG {
            std::cout << "No permissions to send to " << destination.address()
                      << "\n";
        }
        co_return std::make_tuple(std::make_error_code(std::errc::bad_address),
                                  0);
    }
    auto *p = it->second;
    auto channel = p->find_channel_by_port(destination.port());
    if (channel.has_value()) {
        ICE_IN_DEBUG { std::cout << "Send channel data\n"; }
        co_return co_await this->send_channel_data(buffers, *channel);
    }
    // send indication
    ICE_IN_DEBUG { std::cout << "Send indication\n"; }
    std::size_t data_size = net::buffer_size(buffers);

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

    auto buffer_first = net::buffer_sequence_begin(buffers);
    auto buffer_last = net::buffer_sequence_end(buffers);
    std::size_t buffer_count = std::distance(buffer_first, buffer_last);

    boost::container::small_vector<net::const_buffer, 128> indication_buffers;
    indication_buffers.resize(buffer_count + 1);
    indication_buffers.front() = net::const_buffer(buf, n);
    std::transform(buffer_first, buffer_last, indication_buffers.begin() + 1,
                   [](const auto &b) noexcept { return net::const_buffer(b); });

    char pad[4] = {0};
    if (data_size % 4 != 0) {
        indication_buffers.emplace_back(pad, 4 - data_size % 4);
    }
    co_return co_await this->next_layer().async_send_to(
        indication_buffers, this->remote_endpoint(), asio2exec::use_sender);
}

template <class NextLayer>
template <class ConstBufferSequence>
auto datagram_client<NextLayer>::send_channel_data(
    const ConstBufferSequence &buffers, uint16_t channel, auto... self) {
    auto data_size = net::buffer_size(buffers);
    auto buffer_first = net::buffer_sequence_begin(buffers);
    auto buffer_last = net::buffer_sequence_end(buffers);
    std::size_t buffer_count = std::distance(buffer_first, buffer_last);
    boost::container::small_vector<net::const_buffer, 128> channel_buffers(
        buffer_count + 1);
    std::transform(buffer_first, buffer_last, channel_buffers.begin() + 1,
                   [](const auto &b) noexcept { return net::const_buffer(b); });
    return stdexec::just(std::move(channel_buffers), std::array<char, 4>{},
                         std::move(self)...) |
           stdexec::let_value(
               [channel, data_size, this](auto &buffers, auto &header,
                                          const auto &...self) noexcept {
                   binary::write_big<uint16_t>(header.data(), channel);
                   binary::write_big<uint16_t>(header.data() + 2,
                                               (uint16_t)data_size);
                   buffers.front() =
                       net::const_buffer(header.data(), header.size());
                   return this->next_layer().async_send_to(
                       buffers, this->remote_endpoint(), asio2exec::use_sender);
               });
}

template <class NextLayer>
ice::task<bool>
datagram_client<NextLayer>::channel_bind(net::ip::udp::endpoint peer,
                                         uint16_t channel, auto... self) {
    if (!this->_relayed_address) {
        ICE_IN_DEBUG { std::cout << "Haven't allocate.\n"; }
        co_return false;
    }
    if ((this->_relayed_address->address().is_v4() && !peer.address().is_v4()) ||
        (this->_relayed_address->address().is_v6() && !peer.address().is_v6())) {
        ICE_IN_DEBUG {
            std::cout << "Peer address is not the same type as the relayed "
                         "address.\n";
        }
        co_return false;
    }
    ICE_IN_DEBUG {
        std::cout << "Bind or refresh channel: {" << peer.address() << ":"
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
    auto it = this->_ip_to_channel.find(peer.address());
    if (it == this->_ip_to_channel.end()) {
        auto p = std::make_shared<datagram_client<NextLayer>::permission_state>(
            peer.address(), *this);
        p->add_channel(peer.port(), channel);
        p->start();
    } else
        it->second->add_channel(peer.port(), channel);
    co_return true;
}

template <class NextLayer>
ice::task<std::expected<ice::message, std::error_code>>
datagram_client<NextLayer>::read(
    typename datagram_client<NextLayer>::endpoint_type &from, auto... self) {
    if (!this->is_running())
        co_return std::unexpected(
            std::make_error_code(std::errc::invalid_argument));
    auto &turn_q = this->_pool.get_pool(message_type::turn_channel);
    auto &stun_q = this->_pool.get_pool(message_type::stun);
    while (this->is_running()) {
        while (!turn_q.empty()) {
            auto it = std::ranges::find_if(
                turn_q, [this](const message_pool::value_type &v) noexcept {
                    const auto &msg = v.first;
                    const auto &ep = v.second;
                    assert(msg.type() == message_type::turn_channel);
                    return ep == this->remote_endpoint();
                });
            if (it == turn_q.end())
                break;
            auto [msg, ep] = std::move(*it);
            turn_q.erase(it);

            uint16_t channel_number = binary::read_big<uint16_t>(msg.data());
            uint16_t len = binary::read_big<uint16_t>((char *)msg.data() + 2);
            auto ip_it = this->_channel_to_ip.find(channel_number);
            if (ip_it == this->_channel_to_ip.end()) {
                // drop
                continue;
            }

            auto *permission = ip_it->second;
            from = typename datagram_client<NextLayer>::endpoint_type(
                permission->ip(),
                *permission->find_port_by_channel(channel_number));
            msg += 4;
            co_return std::move(msg);
        }
        while (!stun_q.empty()) {
            auto it = std::ranges::find_if(
                stun_q, [this](const message_pool::value_type &v) noexcept {
                    const auto &msg = v.first;
                    const auto &ep = v.second;
                    assert(msg.type() == message_type::stun);
                    auto cls = stun::message::get_class(msg.data(), msg.size());
                    auto method =
                        stun::message::get_method(msg.data(), msg.size());
                    return ep == this->remote_endpoint() &&
                           ((cls == stun::class_t::STUN_CLASS_INDICATION &&
                             method == stun::method_t::STUN_METHOD_DATA) ||
                            cls == stun::class_t::STUN_CLASS_RESP_SUCCESS ||
                            cls == stun::class_t::STUN_CLASS_RESP_ERROR);
                });
            if (it == stun_q.end())
                break;
            auto [msg, ep] = std::move(*it);
            stun_q.erase(it);

            if (stun::message::is_response(msg.data(), msg.size())) {
                // handle response
                if (!this->dispatch(msg.data(), msg.size())) {
                    auto &other_q = this->_pool.get_pool(message_type::unknown);
                    msg.type() = message_type::unknown;
                    other_q.push_back(std::pair{std::move(msg), ep});
                    continue;
                }
                continue;
            }

            stun::message indication;
            if (!indication.parse(msg.data(), msg.size()) ||
                indication.xor_peer_address.size() != 1 ||
                !indication.has_turn_data()) {
                // may be application data
                auto &other_q = this->_pool.get_pool(message_type::unknown);
                msg.type() = message_type::unknown;
                other_q.push_back(std::pair{std::move(msg), ep});
                continue;
            }
            from = typename datagram_client<NextLayer>::endpoint_type(
                indication.xor_peer_address.front().address,
                indication.xor_peer_address.front().port);
            msg = net::const_buffer{indication.turn_data(),
                                    indication.turn_data_size()};
            co_return std::move(msg);
        }
        co_await exec::when_any(this->_pool.wait(message_type::stun),
                                this->_pool.wait(message_type::turn_channel),
                                this->_stop_read_task.get_future());
    }
    co_return std::unexpected(
        std::make_error_code(std::errc::operation_canceled));
}

template <class NextLayer>
template <class MutableBufferSequence>
auto datagram_client<NextLayer>::async_receive_from(
    const MutableBufferSequence &buffers,
    typename datagram_client<NextLayer>::endpoint_type &from, auto... self) {
    auto buffer_first = net::buffer_sequence_begin(buffers);
    auto buffer_last = net::buffer_sequence_end(buffers);
    std::size_t buffer_count = std::distance(buffer_first, buffer_last);
    boost::container::small_vector<net::mutable_buffer, 128> result_buffers(
        buffer_count);
    std::transform(
        buffer_first, buffer_last, result_buffers.begin(),
        [](const auto &b) noexcept { return net::mutable_buffer(b); });
    return stdexec::just(std::move(result_buffers), std::move(self)...) |
           stdexec::let_value(
               [&from, this](auto &buffers, const auto &...self) {
                   return this->read(from) |
                          stdexec::then(
                              [&](std::expected<ice::message, std::error_code>
                                      msg) noexcept
                              -> std::tuple<std::error_code, std::size_t> {
                                  if (!msg)
                                      return std::make_tuple(msg.error(), 0);
                                  return std::make_tuple(
                                      std::error_code{},
                                      net::buffer_copy(buffers, msg->buffer()));
                              });
               });
}

} // namespace ice::turn::impl