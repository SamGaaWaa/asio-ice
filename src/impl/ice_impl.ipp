namespace ice::impl {

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::server_reflexive_candidate(
    std::vector<ice::candidate> &srflx_candidates,
    const ice::candidate &local_candidate, stun::transaction_set &transactions,
    const ice::endpoint &stun_server) noexcept try
{
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
            std::cerr << "server_reflexive_candidate: error or timeout\n"; }
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
    if (auto it = std::ranges::find_if(srflx_candidates, [&](const auto& c) noexcept {
        return c.endpoint == ep;
    }); it != srflx_candidates.end())
        co_return;
    auto srflx = ice::candidate{
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
        .transport = std::move(transport)};
    if (this->_on_local_candidates)
        co_await this->_on_local_candidates(&srflx, 1);
    this->pair_local_candidate(local_candidate);
    srflx_candidates.emplace_back(std::move(srflx));
} catch (const std::exception &e) {
    ICE_IN_DEBUG {
        std::cerr << "server_reflexive_candidate: " << e.what() << "\n";
    }
    co_return;
}

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::server_reflexive_candidate(
    std::vector<ice::candidate> &srflx_candidates,
    const std::vector<ice::candidate> &local_candidates,
    const std::vector<ice::endpoint>& stun_servers) noexcept try
{
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

    exec::async_scope scope;
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
            .transport = transport});
        create_stun_receiver(host_candidates.back().transport);
        transport->start();

        // create TURN clients
        for (const auto& t: this->_config.turn_servers) {
            scope.spawn(create_relayed_candidate(
                component_candidates,
                std::make_shared<typename Self::turn_client_type>(transport, t.address, t.username, t.password),
                transport,
                component));
        }
    }
    if (host_candidates.empty())
        co_return;
    if (this->_config.transport_policy == ice::transport_policy::ALL &&
        this->_on_local_candidates)
        co_await this->_on_local_candidates(host_candidates.data(), host_candidates.size());
    if (this->_config.transport_policy == ice::transport_policy::ALL) {
        for (const auto& c: host_candidates)
            this->pair_local_candidate(c);
        std::ranges::copy(host_candidates, std::back_inserter(component_candidates));
    }
    if (this->_config.transport_policy == ice::transport_policy::ALL &&
        !this->_config.stun_servers.empty() &&
        this->_config.turn_servers.empty()) {
        co_await this->server_reflexive_candidate(component_candidates, host_candidates, this->_config.stun_servers);
    }
    if (!this->_config.turn_servers.empty()) {
        co_await utils::on_scope_empty(scope);
    }
    co_return;
}

template <class Layer>
ice::task<void>
agent_datagram_impl<Layer>::create_relayed_candidate(std::vector<ice::candidate> &component_candidates,
                            std::shared_ptr<typename agent_datagram_impl<Layer>::turn_client_type> client,
                            typename agent_datagram_impl<Layer>::raw_transport_ptr host_transport,
                            uint8_t component) noexcept
{
    auto ret = co_await client->create_allocation(std::chrono::seconds(60 * 5));
    if (!ret) {
        ICE_IN_DEBUG { std::cerr << "Create allocation for \"" << client->local_endpoint().to_string() << "\" failed\n"; }
        co_return;
    }
    const ice::endpoint& relayed = *ret;
    boost::container::small_vector<ice::candidate, 2> tmp;

    if (this->_config.transport_policy == ice::transport_policy::ALL &&
        client->reflex_address())
    {
        tmp.emplace_back(ice::candidate{
            .foundation =
                candidate_foundation(candidate_type::srflx, this->_config.transport,
                                    client->local_endpoint().address(),
                                    client->remote_endpoint().address()),
            .component = component,
            .transport_type = this->_config.transport,
            .priority = candidate_priority(component, candidate_type::srflx),
            .endpoint = *client->reflex_address(),
            .type = candidate_type::srflx,
            .related = client->local_endpoint(),
            .transport = ice::any_transport{std::move(host_transport)}
        });
    }
    ice::any_transport turn_transport{client};
    create_stun_receiver(turn_transport);
    tmp.emplace_back(ice::candidate{
        .foundation =
            candidate_foundation(candidate_type::relayed, this->_config.transport,
                                relayed.address(),
                                client->remote_endpoint().address()),
        .component = component,
        .transport_type = this->_config.transport,
        .priority = candidate_priority(component, candidate_type::relayed),
        .endpoint = relayed,
        .type = candidate_type::relayed,
        .transport = std::move(turn_transport)
    });
    if (this->_on_local_candidates)
        co_await this->_on_local_candidates(tmp.data(), tmp.size());
    for (const auto& c: tmp)
        this->pair_local_candidate(c);
    std::move(tmp.begin(), tmp.end(), std::back_inserter(component_candidates));
    co_return;
}

template <class Layer>
ice::task<void>
agent_datagram_impl<Layer>::do_gather_candidates(auto... self) {
    if (this->_state == agent_state_t::CLOSED ||
        this->_state == agent_state_t::CONNECTED)
        co_return;
    if (this->_config.component_count == 0) {
        throw std::runtime_error("component_count must be greater than 0");
    }
    if (this->_config.transport_policy == ice::transport_policy::RELAY &&
        this->_config.turn_servers.empty())
    {
        throw std::runtime_error{"No TURN servers"};
    }
    utils::scope_guard on_exit([this]() noexcept {
        this->_local_candidates_end = true;
    });
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
        co_await (utils::on_scope_empty(scope) |
                    stdexec::let_value([this] {
                        return this->generate_gathering_end_indication() |
                                stdexec::then([] { return std::monostate{}; });
                    }) |
                    stdexec::let_stopped([this] {
                        return this->generate_gathering_end_indication() |
                                stdexec::then([] { return std::monostate{}; });
                    }) |
                    stdexec::let_error([this](auto) {
                        return this->generate_gathering_end_indication() |
                                stdexec::then([] { return std::monostate{}; });
                    }) |
                    stdexec::stopped_as_optional());
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
void agent_datagram_impl<Layer>::pair_local_candidate(const ice::candidate& c) {
    assert(c.type != ice::candidate_type::srflx && "Should not pair srflx candidates");
    for (const auto& remote_c: this->_remote_candidates) {
        if (!c.can_pair_with(remote_c))
            continue;
        auto priority = ice::candidate_pair::compute_priority(c, remote_c, this->_ice_controlling);
        // The agent prunes each checklist.  This is done by removing a
        // candidate pair if it is redundant with a higher-priority candidate
        // pair in the same checklist.  Two candidate pairs are redundant if
        // their local candidates have the same base and their remote candidates
        // are identical.  The result is a sequence of ordered candidate pairs,
        // called the "checklist" for that data stream.
        auto it = std::ranges::find_if(this->_check_list, [&](const auto& p) noexcept {
            return (p->state() == ice::candidate_pair::state_t::WAITING ||
                    p->state() == ice::candidate_pair::state_t::FROZEN) &&
                    p->local_candidate().endpoint == c.endpoint &&
                    p->remote_candidate().endpoint == remote_c.endpoint &&
                    utils::case_insensitive_equal(p->transport_type(), c.transport_type);
        });
        if (it != this->_check_list.end()) {
            const auto& p = *it;
            if (p->priority() < priority)
                this->_check_list.erase(it);
            else
                continue;
        }
        auto pair = std::make_shared<ice::candidate_pair>(c, remote_c);
        pair->set_priority(priority);
        this->init_pair_state(*pair);
        this->_check_list.emplace_back(std::move(pair));
    }
    if (this->_config.trickle_ice)
        this->sort_check_list();
}

template <class Layer>
void agent_datagram_impl<Layer>::pair_remote_candidate(const ice::candidate& c) {
    for (const auto& local_c: this->_local_candidates) {
        if (!local_c.can_pair_with(c))
            continue;
        auto priority = ice::candidate_pair::compute_priority(local_c, c, this->_ice_controlling);
        // The agent prunes each checklist.  This is done by removing a
        // candidate pair if it is redundant with a higher-priority candidate
        // pair in the same checklist.  Two candidate pairs are redundant if
        // their local candidates have the same base and their remote candidates
        // are identical.  The result is a sequence of ordered candidate pairs,
        // called the "checklist" for that data stream.
        auto it = std::ranges::find_if(this->_check_list, [&](const auto& p) noexcept {
            return (p->state() == ice::candidate_pair::state_t::WAITING ||
                    p->state() == ice::candidate_pair::state_t::FROZEN) &&
                    p->local_candidate().endpoint == local_c.endpoint &&
                    p->remote_candidate().endpoint == c.endpoint &&
                    utils::case_insensitive_equal(p->transport_type(), c.transport_type);
        });
        if (it != this->_check_list.end()) {
            const auto& p = *it;
            if (p->remote_candidate().type == ice::candidate_type::prflx) {
                // If the agent finds a redundancy between two pairs and one of those pairs
                // contains a newly received remote candidate whose type is peer-reflexive,
                // the agent SHOULD discard the pair containing that candidate, set the priority
                // of the existing pair to the priority of the discarded pair, and re-sort the
                // checklist.
                priority = p->priority();
                this->_check_list.erase(it);
            } else if (p->priority() < priority) {
                this->_check_list.erase(it);
            } else
                continue;
        }
        auto pair = std::make_shared<ice::candidate_pair>(local_c, c);
        pair->set_priority(priority);
        this->init_pair_state(*pair);
        this->_check_list.emplace_back(std::move(pair));
    }
    if (this->_config.trickle_ice)
        this->sort_check_list();
}

template <class Layer>
void
agent_datagram_impl<Layer>::init_pair_state(ice::candidate_pair& pair) const noexcept
{
    if (!this->_config.trickle_ice)
        return;
    // TODO
    auto lst = this->_check_list | std::views::filter([&](const auto& p) {
        return p->foundation() == pair.foundation();
    });
    // Rule 1: If the newly formed pair has the lowest component ID and, if the
    // component IDs are equal, the highest priority of any candidate pair for
    // this foundation (i.e., if it is the topmost pair in the column), set the
    // state to Waiting.
    if (std::ranges::all_of(lst, [&](const auto& p) {
        if (p->component() < pair.component())
            return false;
        if (p->component() > pair.component())
            return true;
        return p->priority() <= pair.priority();
    })) {
        pair.set_state(ice::candidate_pair::state_t::WAITING);
        return;
    }
    // Rule 2: If there is at least one pair in the Succeeded state for this
    // foundation, set the state to Waiting.
    if (std::ranges::any_of(lst, [&](const auto& p) {
        return p->state() == ice::candidate_pair::state_t::SUCCEEDED;
    })) {
        pair.set_state(ice::candidate_pair::state_t::WAITING);
        return;
    }
    pair.set_state(ice::candidate_pair::state_t::FROZEN);
}

template <class Layer>
void agent_datagram_impl<Layer>::sort_check_list() noexcept {
    std::ranges::sort(this->_check_list,
                      [](const auto &a, const auto &b) noexcept {
                          return a->priority() > b->priority();
                      });
}

template <class Layer> void agent_datagram_impl<Layer>::close() noexcept {
    this->_state = agent_state_t::CLOSED;
    this->_scope.request_stop();
    this->_triggered_check_queue.clear();
    this->_valid_list.clear();
    this->_check_list.clear();
    for (auto& trans: this->_transactions) {
        trans.stop_retring();
    }
    this->_stun_receivers.clear();
    this->_request_handler_promise.set_stopped();

    // TODO: Should hold a shared_ptr to clear the callback
    this->_on_local_candidates.reset();
}

template <class Layer>
ice::candidate_pair *agent_datagram_impl<Layer>::find_pair(
    const ice::any_transport &transport,
    const ice::candidate &remote_candidate) const noexcept {
    for (const auto &p : this->_check_list) {
        if (p->local_candidate().transport == transport &&
            p->remote_candidate().endpoint == remote_candidate.endpoint &&
            utils::case_insensitive_equal(p->remote_candidate().transport_type, remote_candidate.transport_type)
            )
            return p.get();
    }
    return nullptr;
}

template <class Layer>
ice::task<bool> agent_datagram_impl<Layer>::add_remote_candidate(
    ice::candidate remote_candidate, auto... self) {
    if (this->_state == agent_state_t::CLOSED ||
        this->_state == agent_state_t::CONNECTED ||
        this->_remote_candidates_end)
        co_return false;
    remote_candidate.transport.clear();
    remote_candidate.related.reset();
    if (auto it = std::ranges::find_if(this->_remote_candidates, [&](const auto& c) noexcept {
        return c.endpoint == remote_candidate.endpoint &&
                utils::case_insensitive_equal(c.transport_type, remote_candidate.transport_type);
    }); it != this->_remote_candidates.end()) {
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
    this->create_turn_permission(remote_candidate.endpoint.address());
    this->pair_remote_candidate(remote_candidate);
    this->_remote_candidates.push_back(std::move(remote_candidate));
    co_return true;
}

template <class Layer>
typename agent_datagram_impl<Layer>::check_task
agent_datagram_impl<Layer>::pick_next_pair() noexcept {
    if (this->_check_list.empty()) {
        return {};
    }

    /*
       If the triggered-check queue associated with the checklist
       contains one or more candidate pairs, the agent removes the top
       pair from the queue, performs a connectivity check on that pair,
       puts the candidate pair state to In-Progress, and aborts the
       subsequent steps.
    */
    if (!this->_triggered_check_queue.empty()) {
        auto task = std::move(this->_triggered_check_queue.front());
        this->_triggered_check_queue.pop_front();
        return task;
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
        return { result->shared_from_this(), nullptr, false };
    }

    /*
        If this step is reached, no check could be performed for the
        checklist that was picked.  So, without waiting for timer Ta to
        expire again, select the next checklist in the Running state and
        return to step #1.  If this happens for every single checklist in
        the Running state, meaning there are no remaining candidate pairs
        to perform connectivity checks for, abort these steps.
    */
    return {};
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
    this->_check_list_state = check_list_state_t::RUNNING;
}

template <class Layer>
void agent_datagram_impl<Layer>::check_complete(
    ice::candidate_pair &pair) noexcept {
    if (pair.state() == ice::candidate_pair::state_t::SUCCEEDED) {
        for (auto &p : this->_check_list) {
            if (p->state() == ice::candidate_pair::state_t::FROZEN && p->foundation() == pair.foundation())
                p->set_state(ice::candidate_pair::state_t::WAITING);
        }
        this->default_nominate();
    } else if (pair.state() == ice::candidate_pair::state_t::FAILED) {
        //    If the request fails (Section 7.2.5.2), the agent MUST
        //    remove the candidate pair from the valid list, set the candidate pair
        //    state to Failed, and set the checklist state to Failed.
        std::erase_if(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.source.get() == &pair;
        });
    }
}

template <class Layer>
ice::task<bool> agent_datagram_impl<Layer>::connect(auto... self) noexcept {
    if (this->_state == agent_state_t::CONNECTING ||
        this->_state == agent_state_t::CLOSED ||
        this->_state == agent_state_t::CONNECTED ||
        this->_remote_username.empty() ||
        this->_remote_password.empty() ||
        (!this->_config.trickle_ice && (!this->_local_candidates_end || !this->_remote_candidates_end)
    ))
    {
        ICE_IN_DEBUG {
            std::cout << R"(
                this->_state == agent_state_t::CONNECTING ||
                this->_state == agent_state_t::CLOSED ||
                this->_state == agent_state_t::CONNECTED ||
                this->_remote_username.empty() ||
                this->_remote_password.empty() ||
                (!this->_config.trickle_ice && (!this->_local_candidates_end || !this->_remote_candidates_end)
            )";
        }
        co_return this->_state == agent_state_t::CONNECTED;
    }
    this->sort_check_list();
    this->unfreeze_initial();

    this->_state = agent_state_t::CONNECTING;

    utils::scope_guard on_exit([this]() noexcept {
        for (auto& c: this->_local_candidates)
            c.transport.clear_early_data();
        this->_scope.request_stop();
    });
    net::steady_timer ta{this->context()};
    exec::async_scope scope;
    while (this->_state != agent_state_t::CLOSED &&
            this->_state != agent_state_t::CONNECTED)
        try {
            auto task = this->pick_next_pair();
            if (task.pair) {
                if (_pending_check_count < this->_config.max_pending_check_count) {
                    scope.spawn(
                        stdexec::starts_on(
                            stdexec::inline_scheduler{},
                            this->check(std::move(task))
                        )
                    );
                }
                ta.expires_after(this->_config.connectivity_check_interval);
                if (this->_state == agent_state_t::CONNECTED)
                    break;
            } else if (std::ranges::all_of(this->_check_list, [&](const auto& pair) noexcept {
                return pair->state() == candidate_pair::state_t::SUCCEEDED ||
                        pair->state() == candidate_pair::state_t::FAILED;
            })) {
                if (!this->_config.trickle_ice) {
                    if (!this->all_components_have_valid_pair()) {
                        this->_check_list_state = check_list_state_t::FAILED;
                        break;
                    }
                } else if (this->_local_candidates_end && this->_remote_candidates_end) {
                    if (!this->all_components_have_valid_pair()) {
                        this->_check_list_state = check_list_state_t::FAILED;
                        break;
                    }
                }
                // TODO: Optimize this
                ta.expires_after(this->_config.connectivity_check_interval);
            } else {
                // ta.expires_after(std::chrono::milliseconds(1));
                ta.expires_after(this->_config.connectivity_check_interval);
            }
            auto wakeup = utils::stop_when(
                ta.async_wait(asio2exec::use_sender),
                this->_state.on_change()
            );
            if (auto ret = co_await std::move(wakeup); !ret || *ret)
                break;
        } catch (const std::exception &e) {
            ICE_IN_DEBUG { std::cout << "Exception: " << e.what() << '\n'; }
            break;
        }
    for (auto& trans: this->_transaction_states) {
        trans.transaction->stop_retring();
    }
    scope.request_stop();
    ICE_IN_DEBUG { std::cout << "Waiting for all checks to finish\n"; }
    co_await utils::on_scope_empty(scope);
    ICE_IN_DEBUG { std::cout << "connect: " << (this->_state == agent_state_t::CONNECTED ? "success\n" : "failed\n"); }
    co_return this->_state == agent_state_t::CONNECTED;
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
agent_datagram_impl<Layer>::check(check_task ct) {
    net::steady_timer timer{this->context(), this->_config.connectivity_check_timeout};
    co_await utils::stop_when(
        do_check(std::move(ct)),
        timer.async_wait(asio2exec::use_sender)
    );
}

template <class Layer>
ice::task<void>
agent_datagram_impl<Layer>::do_check(check_task ct) {
    assert(ct.pair);
    auto& pair = *ct.pair;
    ++this->_pending_check_count;
    utils::scope_guard dec_pending_check_count([&]()noexcept {
        --this->_pending_check_count;
        this->_check_complete_notifier.set_value();
    });

    request_result ret = request_result::failed;
    pair.set_state(ice::candidate_pair::state_t::IN_PROGRESS);
    utils::scope_guard on_exit([&]() noexcept {
        pair.set_state(ice::candidate_pair::state_t::FAILED);
        this->check_complete(pair);
    });

    stun::message::integrity subsequent_algo{stun::message::integrity::SHA1};
    for (int i = 0; i < 10; ++i) {
        bool nominate = this->_ice_controlling && !this->_remote_is_lite;
        stun::message req;
        this->build_request(req, pair);
        req.use_candidate = ct.use_candidate;
        if (i == 0) {
            req.integrities.emplace_back(stun::message::integrity::SHA1);
            req.integrities.emplace_back(stun::message::integrity::SHA256);
        } else {
            req.integrities.push_back(subsequent_algo);
        }
        req.set_hmac_key(this->remote_password());

        // Create permission
        if (pair.local_candidate().type == ice::candidate_type::relayed) {
            auto client = pair.local_candidate().transport.template get<typename agent_datagram_impl<Layer>::turn_client_type>();
            assert(client);
            if (!client->has_permission(pair.remote_candidate().endpoint.address())) {
                ICE_IN_DEBUG { std::cout << "Creating permission for: " << pair.remote_candidate().endpoint.address().to_string() << '\n'; }
                bool ok = co_await client->create_permission(pair.remote_candidate().endpoint.address());
                if (!ok) {
                    ICE_IN_DEBUG { std::cout << "Failed to create permission for: " << pair.remote_candidate().endpoint.address().to_string() << '\n'; }
                    co_return;
                }
            }
        }

        ICE_IN_DEBUG { std::cout << "Performing check on pair: " << pair.to_string(0) << '\n'; }
        stun::message resp;
        ret = co_await this->request(pair, req, resp);
        ICE_IN_DEBUG { std::cout << "Check " << (ret == request_result::succeed ? "success: " : (ret == request_result::canceled ? "canceled: " : "failed: ")) << pair.to_string(0) << '\n'; }

        if (ret == request_result::canceled) {
            on_exit.dismiss();
            if (pair.state() == ice::candidate_pair::state_t::IN_PROGRESS &&
                this->_transaction_states.count(&pair) == 0)
            {
                // The last check task
                pair.set_state(ice::candidate_pair::state_t::WAITING);
            }
            co_return;
        }
        if (ret != request_result::succeed) {
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
                ice::hash::random_bytes(&this->_tie_breaker, sizeof(this->_tie_breaker));
                continue;
            }

            co_return;
        }

        // success
        assert(resp.xor_mapped_address);

        auto valid_p = construct_valid_pair(req, resp, ct);
        ice::candidate_pair *to_nominate = nullptr;
        if (auto it = std::ranges::find_if(this->_valid_list, [&](const auto& pp)noexcept {
            const auto& p = pp.pair;
            return p->local_candidate().endpoint == valid_p->local_candidate().endpoint &&
                    p->remote_candidate().endpoint == valid_p->remote_candidate().endpoint &&
                    utils::case_insensitive_equal(p->local_candidate().transport_type, valid_p->local_candidate().transport_type);
        }); it == this->_valid_list.end())
        {
            valid_p->set_state(ice::candidate_pair::state_t::SUCCEEDED);
            to_nominate = valid_p.get();
            this->_valid_list.emplace_back(std::move(valid_p), std::move(ct.pair));
        } else {
            to_nominate = it->pair.get();
        }
        pair.set_state(ice::candidate_pair::state_t::SUCCEEDED);
        if (this->_ice_controlling && req.use_candidate) {
            if (this->set_nominated(*to_nominate))
                co_await this->generate_gathering_end_indication();
        } else if (!this->_ice_controlling && req.use_candidate) {
            if (this->set_nominated(*to_nominate))
                co_await this->generate_gathering_end_indication();
        }
        break;
    }
    if (pair.state() == ice::candidate_pair::state_t::SUCCEEDED) {
        on_exit.dismiss();
        this->check_complete(pair);
    }
    co_return;
}

template <class Layer>
std::shared_ptr<ice::candidate_pair>
agent_datagram_impl<Layer>::construct_valid_pair(
    const stun::message& req,
    const stun::message& resp,
    typename agent_datagram_impl<Layer>::check_task& ct
) {
    auto& pair = *ct.pair;
    assert(resp.xor_mapped_address);
    if (*resp.xor_mapped_address == pair.local_candidate().endpoint) {
        return pair.shared_from_this();
    }
    auto valid_it = std::ranges::find_if(this->_check_list, [&] (const auto& p) noexcept {
        return p->local_candidate().endpoint == *resp.xor_mapped_address &&
                p->remote_candidate().endpoint == pair.remote_candidate().endpoint &&
                utils::case_insensitive_equal(p->local_candidate().transport_type, pair.local_candidate().transport_type);
    });
    if (valid_it != this->_check_list.end())
        return *valid_it;
    auto local_it = std::ranges::find_if(this->_local_candidates, [&](const auto& c) noexcept {
        return c.endpoint == *resp.xor_mapped_address &&
                utils::case_insensitive_equal(c.transport_type, pair.local_candidate().transport_type);
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
            .component = pair.component(),
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
        pair.remote_candidate()
    );
    valid_p->set_priority(this->_ice_controlling);
    return valid_p;
}

template <class Layer>
void agent_datagram_impl<Layer>::build_request(stun::message &req,
                                               ice::candidate_pair &pair) noexcept {
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
    } else {
        req.ice_controlled = this->_tie_breaker;
    }
}

template <class Layer>
ice::task<typename agent_datagram_impl<Layer>::request_result>
agent_datagram_impl<Layer>::request(ice::candidate_pair &pair,
                                    const stun::message &req,
                                    stun::message &resp) noexcept {
    request_result ret = request_result::failed;
    auto it = this->_transactions.lower_bound(req.transaction_id);
    if (it != this->_transactions.end() &&
        it->request.transaction_id == req.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return ret;
    }
    stun::transaction trans(this->context(), req, pair.remote_candidate().endpoint, resp);
    this->_transactions.insert(it, trans);
    transaction_state trans_state{pair, trans};
    this->_transaction_states.insert(trans_state);

    utils::inplace_receiver<void> retry_receiver;
    auto retry_op = retry_receiver.start(stdexec::starts_on(
        asio2exec::scheduler{this->context()}, trans.run(pair.local_candidate().transport)));
    stdexec::start(retry_op);

    while (true) {
        ret = request_result::failed;
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

        ret = request_result::succeed;
        break;
    }
END:
    if (ret == request_result::failed && !trans.is_retring())
        ret = request_result::canceled;
    if (trans.is_linked())
        trans.unlink();
    trans.stop_retring();
    co_await retry_receiver.wait();
    co_return ret;
}

template <class Layer>
void
agent_datagram_impl<Layer>::create_stun_receiver(const ice::any_transport& transport) noexcept {
    this->_stun_receivers.emplace_back(transport, this);
}

template <class Layer>
void
agent_datagram_impl<Layer>::request_handler(
    ice::any_transport& transport,
    const ice::endpoint &source,
    ice::io_buffer_ptr buf)
{
    if (this->_state == agent_state_t::CLOSED)
        return;
    if (this->_outgoing_request_handler_count > 256) {
        ICE_IN_DEBUG{ std::cout << "outgoing_request_handler_count > 256, ignore\n"; }
        return;
    }
    stdexec::start_detached(
        utils::stop_when(
            this->do_handle_request(
                this->shared_from_this(),
                transport,
                source,
                std::move(buf)),
            this->_request_handler_promise.get_future()
        )
    );
}

template <class Layer>
bool
agent_datagram_impl<Layer>::verify_username(std::string_view name) const noexcept
{
    if (this->_remote_username.empty() &&
        (this->_state == agent_state_t::INIT ||
            this->_state == agent_state_t::GATHERING)) {
        // early check
        return name.size() > this->local_username().size() + 1 &&
                std::string_view{name.begin(), name.begin() + this->local_username().size()} == this->local_username() &&
                *(name.begin() + this->local_username().size()) == ':';
    }
    return name.size() == this->local_username().size() + this->_remote_username.size() + 1 &&
            std::string_view{name.begin(), name.begin() + this->local_username().size()} == this->local_username() &&
            *(name.begin() + this->local_username().size()) == ':' &&
            std::string_view{name.begin() + this->local_username().size() + 1, name.end()} == this->_remote_username; 
}

template <class Layer>
ice::task<void>
agent_datagram_impl<Layer>::do_handle_request(
    auto self,
    ice::any_transport transport,
    ice::endpoint source,
    ice::io_buffer_ptr buf)
{
    ++this->_outgoing_request_handler_count;
    utils::scope_guard on_exit([this]() noexcept {
        --this->_outgoing_request_handler_count;
    });
    ICE_IN_DEBUG{
        std::cout << "Connectivity check request from " <<
                    source.to_string() << " to " <<
                    transport.local_endpoint().to_string() << '\n';
    }

    stun::message req, resp;
    if (!req.parse(buf->data(), buf->size()) ||
        req.method != stun::method_t::STUN_METHOD_BINDING ||
        !req.priority) {
        ICE_IN_DEBUG{ std::cout << "Invalid STUN message\n"; }
        co_return;
    }
    buf.reset();

    resp.method = stun::method_t::STUN_METHOD_BINDING;
    resp.transaction_id = req.transaction_id;
    resp.use_fingerprint(true);
    if (!req.integrities.empty()) {
        std::ranges::sort(req.integrities, std::greater<>{});
        resp.integrities.emplace_back(req.integrities.front());
        resp.set_hmac_key(this->local_password());
    }
    if (req.integrities.empty() || req.username.empty()) {
        // Bad Request
        resp.cls = stun::class_t::STUN_CLASS_RESP_ERROR;
        resp.error_code.emplace(400, "Bad Request");
        co_await this->send_stun(transport, resp, source);
        co_return;
    }
    if (!this->verify_username(req.username) ||
        !req.integrities.front().verify(this->local_password(), req)) {
        // Unauthenticated
        resp.cls = stun::class_t::STUN_CLASS_RESP_ERROR;
        resp.error_code.emplace(401, "Unauthenticated");
        co_await this->send_stun(transport, resp, source);
        co_return;
    }

    if (this->_ice_controlling && req.ice_controlling.has_value()) {
        if (this->_tie_breaker >= *req.ice_controlling) {
            resp.cls = stun::class_t::STUN_CLASS_RESP_ERROR;
            resp.error_code.emplace(487, "Role Conflict");
            co_await this->send_stun(transport, resp, source);
            co_return;
        }
        this->switch_role(false);
    } else if (!this->_ice_controlling && req.ice_controlled.has_value()) {
        if (this->_tie_breaker >= *req.ice_controlled) {
            this->switch_role(true);
        } else {
            resp.cls = stun::class_t::STUN_CLASS_RESP_ERROR;
            resp.error_code.emplace(487, "Role Conflict");
            co_await this->send_stun(transport, resp, source);
            co_return;
        }
    }

    resp.cls = stun::class_t::STUN_CLASS_RESP_SUCCESS;
    resp.xor_mapped_address = source;
    co_await this->send_stun(transport, resp, source);

    if (this->_state == agent_state_t::CLOSED ||
        this->_state == agent_state_t::CONNECTED)
        co_return;
    if (this->_state == agent_state_t::INIT ||
        this->_state == agent_state_t::GATHERING) {
        // early check
        do {
            co_await (this->_state.on_change() | stdexec::continues_on(asio2exec::scheduler{this->context()}));
        } while (this->_state == agent_state_t::INIT ||
                this->_state == agent_state_t::GATHERING);
        if (this->_state == agent_state_t::CLOSED ||
            this->_state == agent_state_t::CONNECTED)
            co_return;
    }

    bool use_candidate = !this->_ice_controlling && req.use_candidate;
    ice::candidate *local = nullptr;
    if (auto it = std::ranges::find_if(this->_local_candidates, [&](const auto& c) noexcept {
        return c.transport == transport &&
                utils::case_insensitive_equal(this->_config.transport, c.transport_type);
    }); it != this->_local_candidates.end()) {
        local = &(*it);
    } else {
        ICE_IN_DEBUG{ std::cerr << "Miss a host candidate\n"; }
        co_return;
    }

    ice::candidate *remote = nullptr;
    if (auto it = std::ranges::find_if(this->_remote_candidates, [&](const auto& c) noexcept {
        return c.endpoint == source &&
                utils::case_insensitive_equal(this->_config.transport, c.transport_type);
    }); it != this->_remote_candidates.end()) {
        remote = &(*it);
    } else {
        // Learning Peer-Reflexive Candidates
        this->_remote_candidates.emplace_back(ice::candidate{
            .foundation = utils::random_string(32),
            .component = local->component,
            .transport_type = local->transport_type,
            .priority = *req.priority,
            .endpoint = source,
            .type = ice::candidate_type::prflx
        });
        remote = &this->_remote_candidates.back();
        ICE_IN_DEBUG { std::cout << "Peer-Reflexive Candidate: " << remote->to_string() << '\n'; }
    }

    if (auto it = std::ranges::find_if(this->_check_list, [&](const auto& p) noexcept {
        return p->local_candidate().endpoint == local->endpoint &&
                p->remote_candidate().endpoint == remote->endpoint &&
                utils::case_insensitive_equal(p->local_candidate().transport_type, local->transport_type);
    }); it != this->_check_list.end()) {
        auto& pair = *it;
        if (pair->state() == ice::candidate_pair::state_t::SUCCEEDED) {
            // If the state of this pair is Succeeded, it means that the check
            // previously sent by this pair produced a successful response and
            // generated a valid pair (Section 7.2.5.3.2).  The agent sets the
            // nominated flag value of the valid pair to true.
            if (use_candidate) {
                // nominated the valid pair generated by this pair
                for (auto& pp: this->_valid_list) {
                    if (pp.source.get() == pair.get()) {
                        if (this->set_nominated(*pp.pair))
                            co_await this->generate_gathering_end_indication();
                        break;
                    }
                }
            }
            co_return;
        }
        if (pair->state() == ice::candidate_pair::state_t::IN_PROGRESS) {
            //     If the state of that pair is In-Progress, the agent cancels the
            //  In-Progress transaction.  Cancellation means that the agent
            //  will not retransmit the Binding requests associated with the
            //  connectivity-check transaction, will not treat the lack of
            //  response to be a failure, but will wait the duration of the
            //  transaction timeout for a response.  In addition, the agent
            //  MUST enqueue the pair in the triggered checklist associated
            //  with the checklist, and set the state of the pair to Waiting,
            //  in order to trigger a new connectivity check of the pair.
            //  Creating a new connectivity check enables validating
            //  In-Progress pairs as soon as possible, without having to wait
            //  for retransmissions of the Binding requests associated with the
            //  original connectivity-check transaction.
            auto in_progress_trans = this->_transaction_states.equal_range(pair.get());
            for (auto& trans: std::ranges::subrange{in_progress_trans.first, in_progress_trans.second}) {
                trans.transaction->stop_retring();
            }
            pair->set_state(ice::candidate_pair::state_t::WAITING);
            this->_triggered_check_queue.emplace_back(check_task{
                .pair = pair,
                .triggered_by = pair,
                .use_candidate = use_candidate
            });
            co_return;
        }
        if (!in_triggered_check_queue(*pair)) {
            pair->set_state(ice::candidate_pair::state_t::WAITING);
            this->_triggered_check_queue.emplace_back(check_task{
                .pair = pair,
                .triggered_by = pair,
                .use_candidate = use_candidate
            });
        }
        co_return;
    }
    this->_check_list.push_back(std::make_shared<ice::candidate_pair>(*local, *remote));
    auto* p = this->_check_list.back().get();
    p->set_priority(this->_ice_controlling);
    this->sort_check_list();
    p->set_state(ice::candidate_pair::state_t::WAITING);
    this->_triggered_check_queue.emplace_back(check_task{
        .pair = p->shared_from_this(),
        .triggered_by = p->shared_from_this(),
        .use_candidate = use_candidate
    });
}

template <class Layer>
bool
agent_datagram_impl<Layer>::in_triggered_check_queue(const ice::candidate_pair& pair) const noexcept
{
    return std::ranges::find_if(this->_triggered_check_queue, [&](const auto& ct) noexcept {
        return ct.pair.get() == &pair;
    }) != this->_triggered_check_queue.end();
}

template <class Layer>
template <class Transport>
auto
agent_datagram_impl<Layer>::send_stun(Transport& transport, const stun::message& msg, const ice::endpoint& ep)
{
    auto byte_size = msg.serialized_size();
    return stdexec::just(boost::container::small_vector<std::byte, 1024>(byte_size))
            | stdexec::let_value([&](auto& buf) {
                int n = msg.write_to(buf.data(), buf.size());
                assert(n > 0);
                buf.resize(n);
                return transport.async_send_to(net::const_buffer{buf.data(), buf.size()}, ep);
            });
}

template <class Layer>
bool
agent_datagram_impl<Layer>::stun_receiver::datagram_received(
    io_buffer_ptr &buffer, 
    const ice::endpoint &source)
{
    if (!buffer) [[unlikely]] // ignore empty buffers
        return true;
    const uint8_t b = *buffer->begin();
    if (b > 3)
        return false;
    // STUN
    if (buffer->size() < ice::stun::HEADER_SIZE) {
        // invalid STUN, ignore
        return true;
    }
    auto cls =
        ice::stun::message::get_class(buffer->data(), buffer->size());
    if (cls == stun::class_t::STUN_CLASS_INDICATION)
        return false;
    if (cls == stun::class_t::STUN_CLASS_REQUEST) {
        this->_agent->request_handler(
            this->_transport,
            source,
            std::move(buffer)
        );
        return true;
    }
    if (cls != stun::class_t::STUN_CLASS_RESP_SUCCESS &&
        cls != stun::class_t::STUN_CLASS_RESP_ERROR)
    {
        // invalid STUN, ignore
        return true; 
    }
    // STUN response, possibly came from TURN server
    return dispatch_stun_response(this->_agent->_transactions, source,
                buffer->data(), buffer->size(),
                this->_transport.data());
}

template <class Layer>
bool
agent_datagram_impl<Layer>::set_nominated(ice::candidate_pair& pair) noexcept
{
    if (this->_state == agent_state_t::CLOSED ||
        this->_state == agent_state_t::CONNECTED)
        return false;
    auto it = std::ranges::find_if(this->_valid_list, [&](const auto& pp) noexcept {
        return pp.pair.get() == &pair;
    });
    assert(it != this->_valid_list.end() && "Only valid pairs can be nominated");
    if (it->nominated)
        return false;

    if (std::ranges::any_of(this->_valid_list, [&](const auto& pp) noexcept {
        return pp.pair->component() == it->pair->component() &&
                pp.nominated;
    })) {
        ICE_IN_DEBUG{ std::cerr << "Nominated multiple candidate pairs: " << pair.to_string() << '\n'; }
        return false;
    }

    it->nominated = true;
    // Once a candidate pair for a component of a data stream has been
    // nominated, and the state of the checklist associated with the data
    // stream is Running, the ICE agent MUST remove all candidate pairs
    // for the same component from the checklist and from the triggered-
    // check queue.  If the state of a pair is In-Progress, the agent
    // cancels the In-Progress transaction.  Cancellation means that the
    // agent will not retransmit the Binding requests associated with the
    // connectivity-check transaction, will not treat the lack of
    // response to be a failure, but will wait the duration of the
    // transaction timeout for a response.
    std::erase_if(this->_check_list, [&](const auto& p) noexcept {
        return p->component() == it->pair->component();
    });
    std::erase_if(this->_triggered_check_queue, [&](const auto& ct) noexcept {
        return ct.pair->component() == it->pair->component();
    });
    auto in_progress_trans = this->_transaction_states.equal_range(it->pair.get());
    for (auto& trans: std::ranges::subrange{in_progress_trans.first, in_progress_trans.second}) {
        trans.transaction->stop_retring();
    }

    ICE_IN_DEBUG { std::cout << "New nominated pair: " << it->pair->to_string() << '\n'; }
    for (uint8_t component = 1; component <= this->_config.component_count; ++component) {
        if (component == it->pair->component())
            continue;
        if (std::ranges::none_of(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.pair->component() == component && pp.nominated;
        }))
            return true;
    }
    this->_check_list_state = check_list_state_t::COMPLETED;

    // Once the state of each checklist in the checklist set is Completed,
    // the agent sets the state of the ICE session to Completed.
    ICE_IN_DEBUG { std::cout << "Agent connected\n"; }
    this->_state = agent_state_t::CONNECTED;
    return true;
}

template <class Layer>
boost::container::small_vector<ice::candidate_pair*, 2>
agent_datagram_impl<Layer>::nominated_pairs() const {
    boost::container::small_vector<ice::candidate_pair*, 2> res;
    res.reserve(this->_config.component_count);
    for (uint8_t component = 1; component <= this->_config.component_count; ++component) {
        if (auto it = std::ranges::find_if(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.pair->component() == component && pp.nominated;
        }); it != this->_valid_list.end()) {
            res.push_back(it->pair.get());
        }
    }
    return res;
}

template <class Layer>
void
agent_datagram_impl<Layer>::default_nominate() {
    if (this->_state == agent_state_t::CLOSED ||
        this->_state == agent_state_t::CONNECTED ||
        !this->_ice_controlling)
        return;
    std::ranges::sort(this->_valid_list, [](const auto& a, const auto& b) noexcept {
        return a.pair->priority() > b.pair->priority();
    });
    for (uint8_t component = 1; component <= this->_config.component_count; ++component) {
        if (std::ranges::any_of(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.pair->component() == component && pp.nominated;
        })) {
            continue;
        }
        if (auto it = std::ranges::find_if(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.pair->component() == component;
        }); it != this->_valid_list.end()) {
            auto in_progress_trans = this->_transaction_states.equal_range(it->source.get());
            for (auto& trans: std::ranges::subrange{in_progress_trans.first, in_progress_trans.second}) {
                trans.transaction->stop_retring();
            }
            // std::erase_if(this->_triggered_check_queue, [&](const auto& ct) noexcept {
            //     return ct.pair.get() == it->pair.get();
            // });
            it->source->set_state(ice::candidate_pair::state_t::WAITING);
            this->_triggered_check_queue.emplace_back(check_task{
                .pair = it->source,
                .triggered_by = it->source,
                .use_candidate = true
            });
        }
    }
}

template <class Layer>
bool
agent_datagram_impl<Layer>::all_components_nominated() const noexcept
{
    if (this->_valid_list.size() < this->_config.component_count)
        return false;
    for (uint8_t component = 1; component <= this->_config.component_count; ++component) {
        if (std::ranges::none_of(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.pair->component() == component && pp.nominated;
        }))
            return false;
    }
    return true;
}

template <class Layer>
bool
agent_datagram_impl<Layer>::all_components_have_valid_pair() const noexcept
{
    if (this->_valid_list.size() < this->_config.component_count)
        return false;
    for (uint8_t component = 1; component <= this->_config.component_count; ++component) {
        if (std::ranges::none_of(this->_valid_list, [&](const auto& pp) noexcept {
            return pp.pair->component() == component;
        }))
            return false;
    }
    return true;
}

template <class Layer>
auto
agent_datagram_impl<Layer>::generate_gathering_end_indication() noexcept
{
    bool old = this->_local_candidates_end;
    this->_local_candidates_end = true;
    return utils::if_else(
        stdexec::just(!old && this->_on_local_candidates != nullptr),
        [this] {
            return stdexec::just(std::move(this->_on_local_candidates)) |
                    stdexec::let_value([](auto& cb) {
                        return cb(nullptr, 0);
                    });
        },
        [] { return stdexec::just(); }
    );
}

template <class Layer>
ice::task<void>
agent_datagram_impl<Layer>::free_candidates() {
    if (this->_state != agent_state_t::CONNECTED)
        co_return;
    co_await stdexec::continues_on(asio2exec::scheduler{this->context()});
    const auto now = std::chrono::steady_clock::now();
    const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - this->_state.update_time());
    // Once a checklist has reached the Completed state, the agent SHOULD
    // wait an additional three seconds, and then it can cease responding to
    // checks or generating triggered checks on all local candidates other
    // than the ones that became selected candidates.  Once all ICE sessions
    // have ceased using a given local candidate (a candidate may be used by
    // multiple ICE sessions, e.g., in forking scenarios), the agent can
    // free that candidate.  The three-second delay handles cases when
    // aggressive nomination is used, and the selected pairs can quickly
    // change after ICE has completed.
    if (duration.count() < 3000) {
        net::steady_timer timer{this->context()};
        timer.expires_after(std::chrono::milliseconds(3000 - duration.count()));
        co_await timer.async_wait(asio2exec::use_sender);
    }
    auto nominated_pairs = this->nominated_pairs();
    auto transport_in_use = [&](const auto& transport) noexcept {
        return std::ranges::any_of(nominated_pairs, [&](ice::candidate_pair* pair) noexcept {
            return pair->local_candidate().transport == transport;
        });
    };

    boost::container::flat_multimap<typename agent_datagram_impl<Layer>::turn_client_type*, net::ip::address> in_use_permissions;
    for (auto pair: nominated_pairs) {
        if (pair->local_candidate().type != ice::candidate_type::relayed)
            continue;
        auto client = pair->local_candidate().transport.template get<typename agent_datagram_impl<Layer>::turn_client_type>();
        assert(client);
        in_use_permissions.emplace(client, pair->remote_candidate().endpoint.address());
    }
    for (auto pair: nominated_pairs) {
        if (pair->local_candidate().type != ice::candidate_type::relayed)
            continue;
        auto client = pair->local_candidate().transport.template get<typename agent_datagram_impl<Layer>::turn_client_type>();
        assert(client);
        auto rng = in_use_permissions.equal_range(client);
        auto permissions_in_use = [&](const net::ip::address& ip) noexcept {
            return std::ranges::any_of(std::ranges::subrange{rng.first, rng.second}, [&](const auto& kv) {
                return kv.second == ip;
            });
        };
        for (const auto& remote_c: this->_remote_candidates) {
            auto remote_ip = remote_c.endpoint.address();
            if (!permissions_in_use(remote_ip))
                client->delete_permission(remote_ip);
        }
    } 

    // Stop handling requests and responses
    std::erase_if(this->_stun_receivers, [&](const auto& receiver) noexcept {
        return !transport_in_use(receiver.transport());
    });
    this->_local_candidates.clear();
    this->_remote_candidates.clear();
    this->_check_list.clear();
    std::erase_if(this->_valid_list, [&](const auto& pair) noexcept {
        return !pair.nominated;
    });
    for (auto& p: this->_valid_list) {
        p.source.reset();
    }
    this->_triggered_check_queue.clear();

    this->_local_candidates.shrink_to_fit();
    this->_remote_candidates.shrink_to_fit();
    this->_check_list.shrink_to_fit();
    this->_valid_list.shrink_to_fit();
    this->_triggered_check_queue.shrink_to_fit();
    ICE_IN_DEBUG{ std::cout << "Candidates freed\n"; }
}

template <class Layer>
void
agent_datagram_impl<Layer>::create_turn_permission(const net::ip::address& ip)
{
    if (this->_state == agent_state_t::CLOSED)
        return;
    for (const auto& local_c: this->_local_candidates) {
        if (local_c.type != ice::candidate_type::relayed)
            continue;
        auto client = local_c.transport.template get<typename agent_datagram_impl<Layer>::turn_client_type>();
        assert(client);
        if (!client->has_permission(ip)) {
            ICE_IN_DEBUG { std::cout << "Creating permission for: " << ip.to_string() << '\n'; }
            this->_scope.spawn(client->create_permission(ip, this->shared_from_this()) | utils::ignore());
        }
    }
}

} // namespace ice::impl