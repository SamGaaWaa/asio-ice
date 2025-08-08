namespace ice::impl {

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::server_reflexive_candidate(
    std::vector<ice::candidate> &srflx_candidates,
    const ice::candidate &local_candidate, auto &client,
    const typename agent_datagram_impl<Layer>::endpoint_type &stun_server,
    auto... self) noexcept try {
    using endpoint_type = std::decay_t<decltype(stun_server)>;

    auto transport = local_candidate.transport;

    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_BINDING;
    req.fill_random_transaction_id();

    stun::message resp;
    endpoint_type from;
    auto result =
        co_await (client.request(transport, stun_server, req, from, resp, 7) |
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
                                 local_candidate.endpoint.address),
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
    const std::vector<ice::candidate> &local_candidates, auto &client,
    const std::vector<typename agent_datagram_impl<Layer>::endpoint_type>
        &stun_servers,
    auto... self) noexcept try {
    using Self = agent_datagram_impl<Layer>;
    using endpoint_type = typename Self::endpoint_type;
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

    for (const auto &endpoint : stun_servers) {
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
                srflx_candidates, local_candidate, client, endpoint));
        }
    }
    co_await utils::on_scope_empty(scope);
} catch (std::exception &e) {
    ICE_IN_DEBUG { std::cerr << e.what() << '\n'; }
    co_return;
}

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::get_component_candidates(
    std::vector<ice::candidate> &component_candidates, auto &stun_client,
    uint8_t component, const std::vector<net::ip::address> &addresses,
    auto... self) {
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
        sock.bind(Self::endpoint_type(address, 0), ec);
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
        co_await this->server_reflexive_candidate(component_candidates,
                                                  host_candidates, stun_client,
                                                  this->_config.stun_servers);
    }

    // TODO: Add TURN candidates

    this->_local_candidates.append_range(
        std::views::as_rvalue(host_candidates));
    co_return;
}

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::gather_candidates(auto... self) {
    if (this->_config.component_count == 0) {
        throw std::runtime_error("component_count must be greater than 0");
    }
    ice::stun::client<Layer, true> stun_client(this->_ctx);
    std::vector<net::ip::address> addresses =
        get_local_addresses(this->_config.use_ipv4, this->_config.use_ipv6);

    if (this->_config.component_count == 1) {
        co_await get_component_candidates(this->_local_candidates, stun_client,
                                          1, addresses);
        co_return;
    }

    exec::async_scope scope;
    // TODO: use components set
    for (uint8_t component = 1; component <= this->_config.component_count;
         ++component) {
        scope.spawn(get_component_candidates(
            this->_local_candidates, stun_client, component, addresses));
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
    for (auto &p : this->_check_list) {
        p->set_request_handler(nullptr);
    }
}

template <class Layer>
ice::candidate_pair_base *agent_datagram_impl<Layer>::find_pair(
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
            auto c_pair = std::make_shared<ice::candidate_pair<
                typename agent_datagram_impl<Layer>::stun_client_type>>(
                c, remote_candidate, this->_stun_client);
            c_pair->set_request_handler(
                [this, p = this->shared_from_this()](ice::candidate_pair_base &,
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

} // namespace ice::impl