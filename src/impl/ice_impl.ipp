namespace ice::impl {

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::server_reflexive_candidate(
    std::vector<ice::candidate> &srflx_candidates,
    const ice::candidate &local_candidate, stun::transaction_set &transactions,
    const ice::endpoint &stun_server, auto... self) noexcept try {
    auto transport = local_candidate.transport;

    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_BINDING;
    req.fill_random_transaction_id();

    stun::message resp;
    ice::endpoint from;
    auto result = co_await (stun::basic_request(transport, transactions, req,
                                                stun_server, resp, from, 7) |
                            stdexec::stopped_as_optional());
    if (!result || !*result) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_candidate: \n"
                      << "local endpoint: "
                      << transport.local_endpoint().to_string() << "\n"
                      << "stun server: " << stun_server.address() << ':'
                      << stun_server.port() << "\n\n";
        }
        co_return;
    }
    if (from != stun_server) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_candidate: from != stun_server\n";
        }
        co_return;
    }
    ice::endpoint ep;
    if (resp.xor_mapped_address)
        ep = *resp.xor_mapped_address;
    else if (resp.mapped_address)
        ep = *resp.mapped_address;
    else
        co_return;
    srflx_candidates.emplace_back(ice::candidate{
        .foundation =
            candidate_foundation(candidate_type::srflx, this->_config.transport,
                                 local_candidate.endpoint.address(),
                                 stun_server.address()),
        .component = local_candidate.component,
        .transport_type = this->_config.transport,
        .priority = candidate_priority(local_candidate.component,
                                       candidate_type::srflx),
        .endpoint = ep,
        .type = candidate_type::srflx,
        .related = local_candidate.endpoint,
        .transport = std::move(transport)});
} catch (std::exception &e) {
    ICE_IN_DEBUG {
        std::cerr << "server_reflexive_candidate: " << e.what() << "\n";
    }
    co_return;
}

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::server_reflexive_candidate(
    std::vector<ice::candidate> &srflx_candidates,
    const std::vector<ice::candidate> &local_candidates,
    const std::vector<ice::endpoint> &stun_servers, auto... self) noexcept try {
    using Self = agent_datagram_impl<Layer>;
    if (stun_servers.empty()) {
        ICE_IN_DEBUG { std::cerr << "no STUN servers\n"; }
        co_return;
    }
    exec::async_scope scope;

    ICE_IN_DEBUG {
        for (const auto &endpoint : stun_servers) {
            std::cout << "resolved STUN server: " << endpoint.address() << ':'
                      << endpoint.port() << '\n';
        }
    }

    // TODO: Use global transaction set
    std::unique_ptr<stun::transaction_set[]> transaction_sets =
        std::make_unique<stun::transaction_set[]>(stun_servers.size());
    for (std::size_t i = 0; i < stun_servers.size(); ++i) {
        const auto &endpoint = stun_servers[i];
        for (const auto &local_candidate : local_candidates) {
            const typename Self::raw_transport *transport =
                local_candidate.transport.get<typename Self::raw_transport>();
            assert(transport);
            if (transport->local_endpoint().address().is_v4() &&
                !endpoint.address().is_v4())
                continue;
            if (transport->local_endpoint().address().is_v6() &&
                !endpoint.address().is_v6())
                continue;
            scope.spawn(this->server_reflexive_candidate(
                srflx_candidates, local_candidate, transaction_sets[i],
                endpoint));
        }
    }
    co_await utils::on_scope_empty(scope);
} catch (std::exception &e) {
    ICE_IN_DEBUG { std::cerr << e.what() << '\n'; }
    co_return;
}

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::get_component_candidates(
    std::vector<ice::candidate> &component_candidates, uint8_t component,
    const std::vector<net::ip::address> &addresses, auto... self) {
    using Self = agent_datagram_impl<Layer>;

    if (addresses.empty()) {
        co_return;
    }

    std::vector<ice::candidate> host_candidates;
    host_candidates.reserve(addresses.size());
    for (const auto &address : addresses) {
        if ((!this->_config.use_ipv4 && address.is_v4()) ||
            (!this->_config.use_ipv6 && address.is_v6()) ||
            (!this->_config.use_loopback && address.is_loopback())) {
            ICE_IN_DEBUG {
                std::cerr << "Skipping address: " << address << '\n';
            }
            continue;
        }
        if (address.is_v6()) {
            net::ip::address_v6 addr = address.to_v6();
            if (addr.is_site_local() || addr.is_v4_mapped()) {
                ICE_IN_DEBUG {
                    std::cerr << "Skipping address: " << address << '\n';
                }
                continue;
            }
        }
        Layer sock(this->_ctx);
#if ASIOICE_USE_BOOST_ASIO
        boost::system::error_code ec;
#else
        std::error_code ec;
#endif
        if (address.is_v4()) {
            sock.open(net::ip::udp::v4(), ec);
        } else {
            sock.open(net::ip::udp::v6(), ec);
        }
        if (ec) {
            ICE_IN_DEBUG {
                std::cerr << "Failed to open socket: " << ec.message() << '\n';
            }
            continue;
        }

        // TODO: support port ranges
        sock.bind(ice::endpoint(address, 0), ec);
        if (ec) {
            ICE_IN_DEBUG {
                std::cerr << "Failed to bind socket: " << ec.message() << '\n';
            }
            continue;
        }

        auto transport =
            std::make_shared<Self::raw_transport>(this->_ctx, std::move(sock));
        transport->start();

        ICE_IN_DEBUG {
            std::cout << "Host transport bound to "
                      << transport->local_endpoint().address() << ':'
                      << transport->local_endpoint().port() << '\n';
        }

        host_candidates.emplace_back(ice::candidate{
            .foundation = candidate_foundation(
                candidate_type::host, this->_config.transport, address),
            .component = component,
            .transport_type = this->_config.transport,
            .priority = candidate_priority(component, candidate_type::host),
            .endpoint =
                ice::endpoint{address, transport->local_endpoint().port()},
            .type = candidate_type::host,
            .transport = std::move(transport)});
    }
    if (host_candidates.empty())
        co_return;

    if (!this->_config.stun_servers.empty() && !this->_config.turn_server) {
        co_await this->server_reflexive_candidate(
            component_candidates, host_candidates, this->_config.stun_servers);
    }

    // TODO: Add TURN candidates
    std::move(host_candidates.begin(), host_candidates.end(),
              std::back_inserter(this->_local_candidates));
    // this->_local_candidates.insert(this->_local_candidates.end(),
    // host_candidates));
    co_return;
}

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::gather_candidates(auto... self) {
    if (this->_config.component_count == 0) {
        throw std::runtime_error("component_count must be greater than 0");
    }
    std::vector<net::ip::address> addresses =
        get_local_addresses(this->_config.use_ipv4, this->_config.use_ipv6);

    if (this->_config.component_count == 1) {
        co_await get_component_candidates(this->_local_candidates, 1,
                                          addresses);
        co_return;
    }

    exec::async_scope scope;
    // TODO: use components set
    for (uint8_t component = 1; component <= this->_config.component_count;
         ++component) {
        scope.spawn(get_component_candidates(this->_local_candidates, component,
                                             addresses));
    }
    co_await utils::on_scope_empty(scope);
}

inline bool __validate_remote_candidate(const ice::candidate &c) noexcept {
    switch (c.type) {
    case ice::candidate_type::host:
    case ice::candidate_type::srflx:
    case ice::candidate_type::relayed:
        return true;
    default:
        return false;
    }
}

template <class Layer>
void agent_datagram_impl<Layer>::sort_check_list() noexcept {
    std::ranges::sort(this->_check_list,
                      [](const auto &a, const auto &b) noexcept {
                          return a->priority() > b->priority();
                      });
}

template <class Layer> void agent_datagram_impl<Layer>::clear() noexcept {
    this->_triggered_check_queue.clear();
    for (auto &p : this->_check_list) {
        p->set_request_handler(nullptr);
    }
}

template <class Layer>
ice::candidate_pair *agent_datagram_impl<Layer>::find_pair(
    const ice::any_transport &transport,
    const ice::candidate &remote_candidate) const noexcept {
    for (const auto &p : this->_check_list) {
        if (p->local_candidate().transport == transport &&
            p->remote_candidate() == remote_candidate)
            return p.get();
    }
    return nullptr;
}

template <class Layer>
ice::task<bool> agent_datagram_impl<Layer>::add_remote_candidate(
    ice::candidate remote_candidate, auto... self) {
    remote_candidate.transport.clear();
    remote_candidate.related.reset();
    if (auto it = std::ranges::find(this->_remote_candidates, remote_candidate);
        it != this->_remote_candidates.end()) {
        ICE_IN_DEBUG {
            std::cout << "Remote candidate already exists: "
                      << remote_candidate.to_string() << '\n';
        }
        co_return true;
    }

    // TODO: resolve mDNS hostnames
    if (false) {
    }

    if (!__validate_remote_candidate(remote_candidate)) {
        ICE_IN_DEBUG {
            std::cout << "Invalid remote candidate: "
                      << remote_candidate.to_string() << '\n';
        }
        co_return false;
    }

    this->_remote_candidates.push_back(remote_candidate);

    for (const auto &c : this->_local_candidates) {
        if (c.can_pair_with(remote_candidate) &&
            this->find_pair(c.transport, remote_candidate) == nullptr) {
            auto c_pair = std::make_shared<ice::candidate_pair>(
                c, remote_candidate, this->_transactions);
            c_pair->set_request_handler(
                [this, p = this->shared_from_this()](const ice::endpoint &from,
                                                     const ice::endpoint &to,
                                                     ice::io_buffer_ptr req) {
                    // TODO: Handle STUN requests
                });
            c_pair->set_priority(this->_ice_controlling);
            this->_check_list.emplace_back(std::move(c_pair));
        }
    }

    this->sort_check_list();
    co_return true;
}

template <class Layer>
ice::candidate_pair *agent_datagram_impl<Layer>::pick_next_pair() noexcept {
    if (this->_check_list.empty()) {
        return nullptr;
    }

    /*
       If the triggered-check queue associated with the checklist
       contains one or more candidate pairs, the agent removes the top
       pair from the queue, performs a connectivity check on that pair,
       puts the candidate pair state to In-Progress, and aborts the
       subsequent steps.
    */
    if (!this->_triggered_check_queue.empty()) {
        auto &p = this->_triggered_check_queue.front();
        this->_triggered_check_queue.pop_front();
        p.set_state(ice::candidate_pair::state_t::IN_PROGRESS);
        return &p;
    }

    if (std::ranges::none_of(this->_check_list, [](const auto &p) noexcept {
            return p->state() == ice::candidate_pair::state_t::WAITING;
        })) {
        /*
            If there is no candidate pair in the Waiting state, and if there
            are one or more pairs in the Frozen state, the agent checks the
            foundation associated with each pair in the Frozen state.  For a
            given foundation, if there is no pair (in any checklist in the
            checklist set) in the Waiting or In-Progress state, the agent
            puts the candidate pair state to Waiting and continues with the
            next step.
        */
        for (auto &p : this->_check_list) {
            if (p->state() != ice::candidate_pair::state_t::FROZEN)
                continue;
            if (std::ranges::none_of(
                    this->_check_list, [&p](const auto &pp) noexcept {
                        return p->foundation() == pp->foundation() &&
                               pp->state() ==
                                   ice::candidate_pair::state_t::IN_PROGRESS;
                    })) {
                p->set_state(ice::candidate_pair::state_t::WAITING);
            }
        }
    }

    candidate_pair *result = nullptr;
    for (auto &p : this->_check_list) {
        if (p->state() != ice::candidate_pair::state_t::WAITING)
            continue;
        if (!result || p->priority() > result->priority()) {
            result = p.get();
            continue;
        }
        if (p->priority() == result->priority() &&
            p->component() < result->component()) {
            result = p.get();
        }
    }
    if (result) {
        /*
            If there are one or more candidate pairs in the Waiting state,
            the agent picks the highest-priority candidate pair (if there are
            multiple pairs with the same priority, the pair with the lowest
            component ID is picked) in the Waiting state, performs a
            connectivity check on that pair, puts the candidate pair state to
            In-Progress, and aborts the subsequent steps.
        */
        result->set_state(ice::candidate_pair::state_t::IN_PROGRESS);
        return result;
    }

    /*
        If this step is reached, no check could be performed for the
        checklist that was picked.  So, without waiting for timer Ta to
        expire again, select the next checklist in the Running state and
        return to step #1.  If this happens for every single checklist in
        the Running state, meaning there are no remaining candidate pairs
        to perform connectivity checks for, abort these steps.
    */
    return nullptr;
}

template <class Layer>
void agent_datagram_impl<Layer>::unfreeze_initial() noexcept {
    ice::small_set<std::string_view> seen_foundations;
    std::vector<ice::candidate_pair *> pairs(this->_check_list.size(), nullptr);
    std::transform(this->_check_list.begin(), this->_check_list.end(),
                   pairs.begin(), [](auto &p) noexcept { return p.get(); });
    std::ranges::sort(pairs, [](const auto &a, const auto &b) noexcept {
        if (a->component() == b->component())
            return a->priority() > b->priority();
        return a->component() < b->component();
    });
    for (auto p : pairs) {
        if (seen_foundations.contains(p->foundation()))
            continue;
        seen_foundations.insert(p->foundation());
        p->set_state(ice::candidate_pair::state_t::WAITING);
    }
}

template <class Layer>
void agent_datagram_impl<Layer>::check_complete(
    const ice::candidate_pair &pair) noexcept {
    if (pair.state() != ice::candidate_pair::state_t::SUCCEEDED)
        return;
    for (auto &p : this->_check_list) {
        if (p->state() == ice::candidate_pair::state_t::FROZEN &&
            p->foundation() == pair.foundation())
            p->set_state(ice::candidate_pair::state_t::WAITING);
    }
}

template <class Layer>
ice::task<bool> agent_datagram_impl<Layer>::connect(auto... self) noexcept {
    this->unfreeze_initial();

    // TODO: Handle early checks
    {}

    net::steady_timer ta{this->context()};
    exec::async_scope scope;
    ice::shared_promise<bool> done;
    while (true)
        try {
            utils::scope_guard on_err([&]() noexcept { scope.request_stop(); });
            auto *p = this->pick_next_pair();
            if (!p) {
                if (std::ranges::any_of(
                        this->_check_list, [](const auto &p) noexcept {
                            return p->state() ==
                                   ice::candidate_pair::state_t::IN_PROGRESS;
                        })) {
                    auto ret = co_await (done.get_future() |
                                         stdexec::stopped_as_optional());
                    if (!ret)
                        break;
                    on_err.dismiss();
                    continue;
                }
                ICE_IN_DEBUG { std::cout << "No pairs to check, exiting\n"; }
                on_err.dismiss();
                break;
            }
            assert(p->state() == ice::candidate_pair::state_t::IN_PROGRESS);
            scope.spawn(
                stdexec::starts_on(asio2exec::scheduler{this->context()},
                                   this->check(*p) |
                                    stdexec::then([&done] {
                                        done.set_value(true);
                                    })));
            ta.expires_after(std::chrono::milliseconds(50));
            if (auto ret = co_await (ta.async_wait(asio2exec::use_sender) |
                                     stdexec::stopped_as_optional());
                !ret)
                break;
            on_err.dismiss();
        } catch (const std::exception &e) {
            ICE_IN_DEBUG { std::cout << "Exception: " << e.what() << '\n'; }
            break;
        }
    ICE_IN_DEBUG { std::cout << "Waiting for all checks to finish\n"; }
    co_await utils::on_scope_empty(scope);
    co_return false;
}

template <class Layer>
void
agent_datagram_impl<Layer>::switch_role(bool ice_controlling) noexcept {
    ICE_IN_DEBUG { std::cout << "Switching to " << (ice_controlling ? "controlling" : "controlled") << " role\n"; }
    this->_ice_controlling = ice_controlling;
    for (auto& p: this->_check_list) {
        p->set_priority(ice_controlling);
    }
    this->sort_check_list();
}

template <class Layer>
ice::task<void>
agent_datagram_impl<Layer>::check(ice::candidate_pair &pair) noexcept {
    if (pair.state() != ice::candidate_pair::state_t::WAITING) {
        ICE_IN_DEBUG { std::cout << "This check finished or had been canceled\n"; }
        co_return;
    }
    pair.set_state(ice::candidate_pair::state_t::IN_PROGRESS);
    utils::scope_guard on_err([&]() noexcept {
        if (pair.state() == ice::candidate_pair::state_t::IN_PROGRESS) {
            pair.set_state(ice::candidate_pair::state_t::FAILED);
            this->check_complete(pair);
        }
        else {
            ICE_IN_DEBUG { std::cout << "Current check had been canceled\n"; }
        }
    });
    bool nominate = this->_ice_controlling && !this->_remote_is_lite;

    stun::message::integrity subsequent_algo{stun::message::integrity::SHA1};
    for (int i = 0; ; ++i) {
        stun::message req;
        this->build_request(req, pair, nominate);
        if (i == 0) {
            req.integrities.emplace_back(stun::message::integrity::SHA1);
            req.integrities.emplace_back(stun::message::integrity::SHA256);
        } else {
            req.integrities.push_back(subsequent_algo);
        }
        req.set_hmac_key(this->remote_password());

        ICE_IN_DEBUG { std::cout << "Performing check on pair: " << pair.to_string(0) << '\n'; }
        stun::message resp;
        bool ret = co_await this->request(pair, req, resp);
        ICE_IN_DEBUG { std::cout << "Check " << (ret ? "success: " : "failed: ") << pair.to_string(0) << '\n'; }

        if (!ret) {
            co_return;
        }
        assert(!resp.integrities.empty());
        subsequent_algo = resp.integrities.back();
        if (resp.cls == stun::class_t::STUN_CLASS_RESP_ERROR) {
            assert(resp.error_code.has_value());
            ICE_IN_DEBUG { std::cout << "ERROR response with error code: " << resp.error_code->reason << '\n'; }
            
            if (resp.error_code->code == 487) {
                // switch role
                if (req.ice_controlled)
                    this->switch_role(true);
                else if (req.ice_controlling)
                    this->switch_role(false);
                assert(!pair.in_triggered_queue());
                pair.set_state(ice::candidate_pair::state_t::WAITING);
                this->_triggered_check_queue.push_back(pair);
                // TODO: change tiebreaker value 
                continue;
            }

            co_return;
        }
        
        // success
        assert(resp.xor_mapped_address);

        this->_valid_list.push_back(construct_valid_pair(req, resp, pair));
        pair.set_state(ice::candidate_pair::state_t::SUCCEEDED);
        this->_valid_list.back()->set_state(ice::candidate_pair::state_t::SUCCEEDED);
        for (auto& p: this->_check_list) {
            if (p->state() == ice::candidate_pair::state_t::FROZEN &&
                p->foundation() == pair.foundation())
            {
                p->set_state(ice::candidate_pair::state_t::WAITING);
            }
        }
        break;
    }

    on_err.dismiss();
    this->check_complete(pair);
    co_return;
}

template <class Layer>
std::shared_ptr<ice::candidate_pair>
agent_datagram_impl<Layer>::construct_valid_pair(
    const stun::message& req,
    const stun::message& resp,
    ice::candidate_pair& pair
) noexcept {
    if (*resp.xor_mapped_address == pair.local_candidate().endpoint) {
        // host local candidate
        return pair.shared_from_this();
    }
    auto valid_it = std::ranges::find_if(this->_check_list, [&] (const auto& p) noexcept {
        // TODO
        return *resp.xor_mapped_address == p->local_candidate().endpoint &&
                p->remote_candidate() == pair.remote_candidate();
    });
    if (valid_it != this->_check_list.end())
        return *valid_it;
    auto local_it = std::ranges::find_if(this->_local_candidates, [&](const auto& c) noexcept {
        return *resp.xor_mapped_address == c.endpoint &&
                c.component == pair.local_candidate().component &&
                std::ranges::equal(c.transport_type, pair.local_candidate().transport_type,
                                    [](char a, char b) noexcept {
                                        return std::tolower(a) == std::tolower(b);
                                    }) &&
                std::ranges::equal(c.tcptype, pair.local_candidate().tcptype,
                                    [](char a, char b) noexcept {
                                        return std::tolower(a) == std::tolower(b);
                                    });
    });
    if (local_it == this->_local_candidates.end()) {
        // Peer-Reflexive Candidates
        this->_local_candidates.emplace_back(ice::candidate{
            .foundation = candidate_foundation(
                ice::candidate_type::prflx,
                pair.local_candidate().transport_type,
                pair.local_candidate().type == ice::candidate_type::host ?
                    pair.local_candidate().endpoint.address() :
                    pair.local_candidate().related.value().address(),
                pair.remote_candidate().endpoint.address()
            ),
            .component = pair.local_candidate().component,
            .transport_type = pair.local_candidate().transport_type,
            .priority = *req.priority,
            .endpoint = *resp.xor_mapped_address,
            .type = ice::candidate_type::prflx,
            .related = pair.local_candidate().endpoint,
            .transport = pair.local_candidate().transport
        });
        ICE_IN_DEBUG { std::cout << "Peer-Reflexive Candidate: " << local_it->to_string() << '\n'; }
        local_it = this->_local_candidates.begin() + (this->_local_candidates.size() - 1);
    }
    auto valid_p = std::make_shared<ice::candidate_pair>(
        *local_it,
        pair.remote_candidate(),
        this->_transactions
    );
    valid_p->set_priority(this->_ice_controlling);
    return valid_p;
}

template <class Layer>
void agent_datagram_impl<Layer>::build_request(stun::message &req,
                                               ice::candidate_pair &pair,
                                               bool nominate) noexcept {
    std::string tx_username;
    tx_username.resize_and_overwrite(
        this->local_username().size() + this->remote_username().size() + 1,
        [&](char *p, std::size_t n) -> std::size_t {
            std::ranges::copy(this->remote_username(), p);
            p[this->remote_username().size()] = ':';
            std::ranges::copy(this->local_username(),
                              p + this->remote_username().size() + 1);
            return this->local_username().size() +
                   this->remote_username().size() + 1;
        });

    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_BINDING;
    req.fill_random_transaction_id();
    req.username = std::move(tx_username);
    req.priority =
        ice::candidate_priority(pair.component(), candidate_type::prflx);
    req.use_fingerprint(true);

    if (this->_ice_controlling) {
        req.ice_controlling = this->_tie_breaker;
        if (nominate) {
            req.use_candidate = true;
        }
    } else {
        req.ice_controlled = this->_tie_breaker;
    }
}

template <class Layer>
ice::task<bool>
agent_datagram_impl<Layer>::request(ice::candidate_pair &pair,
                                    const stun::message &req,
                                    stun::message &resp) noexcept {
    auto it = this->_transactions.lower_bound(req.transaction_id);
    if (it != this->_transactions.end() &&
        it->request.transaction_id == req.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return false;
    }
    stun::transaction trans(this->context(), req, pair.remote_candidate().endpoint, resp);
    this->_transactions.insert(it, trans);

    bool ret = false;
    utils::inplace_receiver<std::error_code> retry_receiver;
    auto retry_op = retry_receiver.start(stdexec::starts_on(
        asio2exec::scheduler{this->context()}, trans.run(pair.local_candidate().transport)));
    stdexec::start(retry_op);

    while (true) {
        ret = false;
        auto new_state =
            co_await (trans.on_state_change() | stdexec::stopped_as_optional());
        if (!new_state.has_value()) {
            goto END;
        }
        if (trans.state() == stun::transaction::state_t::ERROR) {
            goto END;
        }
        assert(trans.state() == stun::transaction::state_t::DONE);
        assert(resp.transaction_id == req.transaction_id);
        assert(resp.is_response());

        // The client looks for the MESSAGE-INTEGRITY or the MESSAGE-INTEGRITY-
        // SHA256 attribute in the response.  If present and if the client only
        // sent one of the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
        // attributes in the request (because of the external indication in
        // Section 9.1.2 or because this is a subsequent request as defined in
        // Section 9.1.5), the algorithm in the response has to match;
        // otherwise, the response MUST be discarded.
        if (resp.integrities.empty() || resp.integrities.size() > 2) {
            ICE_IN_DEBUG { std::cout << "Integrity algorithm mismatch\n"; }
            continue;
        }
        if (resp.integrities.size() == 1) {
            if (!std::ranges::contains(req.integrities, resp.integrities.front())) {
                ICE_IN_DEBUG { std::cout << "Integrity algorithm mismatch\n"; }
                continue;
            }
        } else {
            std::ranges::sort(resp.integrities);
            if (resp.integrities != req.integrities) {
                ICE_IN_DEBUG { std::cout << "Integrity algorithm mismatch\n"; }
                continue;
            }
        }

        // The client then computes the message integrity over the response as
        // defined in Section 14.5 for the MESSAGE-INTEGRITY attribute or
        // Section 14.6 for the MESSAGE-INTEGRITY-SHA256 attribute, using the
        // same password it utilized for the request.  If the resulting value
        // matches the contents of the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-
        // SHA256 attribute, respectively, the response is considered
        // authenticated.  If the value does not match, or if both MESSAGE-
        // INTEGRITY and MESSAGE-INTEGRITY-SHA256 are absent, the processing
        // depends on whether the request was sent over a reliable or an
        // unreliable transport.
        if (std::any_of(resp.integrities.begin(), resp.integrities.end(),
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

        if (trans.response_transport != pair.local_candidate().transport.data() ||
            trans.response_source != pair.remote_candidate().endpoint)
        {
            ICE_IN_DEBUG { std::cout << "Non-Symmetric Transport Addresses\n"; }
            break;
        }

        if (resp.cls == stun::class_t::STUN_CLASS_RESP_ERROR) {
            if (!resp.error_code.has_value()) {
                ICE_IN_DEBUG { std::cout << "Unknown error\n"; }
                break;
            }
        } else {
            if (!resp.xor_mapped_address.has_value()) {
                ICE_IN_DEBUG { std::cout << "Invalid response\n"; }
                break;
            }
        }

        ret = true;
        break;
    }
END:
    if (trans.is_linked())
        trans.unlink();
    trans.stop_retring();
    co_await retry_receiver.wait();
    co_return ret;
}

} // namespace ice::impl