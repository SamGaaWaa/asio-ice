namespace ice::impl {

template <class Layer>
ice::task<void> agent_datagram_impl<Layer>::resolve_server(
    net::ip::basic_resolver<typename Layer::endpoint_type::protocol_type>
        &resolver,
    std::string_view stun_server,
    std::vector<typename Layer::endpoint_type> &endpoints) {
    if (stun_server.size() < 1)
        co_return;
    std::string_view host, port;
    {
        auto idx = stun_server.find_last_of(':');
        if (idx == std::string_view::npos) {
            host = stun_server;
            port = "";
        } else {
            host = std::string_view{stun_server.data(), idx};
            port = std::string_view{stun_server.begin() + idx + 1,
                                    stun_server.end()};
        }
    }

    auto opt = co_await (resolver.async_resolve(
                             host, port, net::as_tuple(asio2exec::use_sender)) |
                         stdexec::stopped_as_optional());
    if (!opt) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_endpoint timeout: " << stun_server
                      << '\n';
        }
        co_return;
    }
    const auto &[ec, result] = *opt;
    if (ec) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_endpoint error " << stun_server
                      << ": " << ec.message() << '\n';
        }
        co_return;
    }
    if (result.empty()) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_endpoint no result: " << stun_server
                      << '\n';
        }
        co_return;
    }

    for (auto it = result.begin(); it != result.end(); ++it) {
        endpoints.push_back(it->endpoint());
    }
}

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
    exec::async_scope &scope, std::vector<ice::candidate> &srflx_candidates,
    const std::vector<ice::candidate> &local_candidates, auto &client,
    const std::vector<std::string> &stun_servers, auto... self) noexcept try {
    using Self = agent_datagram_impl<Layer>;
    using endpoint_type = typename Self::endpoint_type;
    net::ip::basic_resolver<typename endpoint_type::protocol_type> resolver(
        client.context());
    std::vector<endpoint_type> endpoints;

    asio2exec::scheduler sched{this->_ctx};
    for (const auto &server : stun_servers) {
        scope.spawn(stdexec::starts_on(
            sched, resolve_server(resolver, server, endpoints)));
    }
    co_await scope.on_empty();

    if (endpoints.empty()) {
        ICE_IN_DEBUG { std::cerr << "no STUN servers found\n"; }
        co_return;
    }

    ICE_IN_DEBUG {
        for (const auto &endpoint : endpoints) {
            std::cout << "resolved STUN server: " << endpoint.address() << ':'
                      << endpoint.port() << '\n';
        }
    }

    for (const auto &endpoint : endpoints) {
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
            scope.spawn(stdexec::starts_on(
                sched, this->server_reflexive_candidate(srflx_candidates,
                                                        local_candidate, client,
                                                        endpoint)));
        }
    }
    co_await scope.on_empty();
} catch (std::exception &e) {
    ICE_IN_DEBUG { std::cerr << e.what() << '\n'; }
    co_return;
}

template <class Layer>
ice::task<std::vector<ice::candidate>>
agent_datagram_impl<Layer>::get_component_candidates(
    auto &stun_client, uint8_t component,
    const std::vector<net::ip::address> &addresses,
    std::chrono::milliseconds timeout, auto... self) {
    using Self = agent_datagram_impl<Layer>;
    std::vector<ice::candidate> result;

    if (addresses.empty()) {
        co_return result;
    }

    std::vector<Self::raw_transport_ptr> host_transports;
    std::vector<ice::candidate> host_candidates;
    host_transports.reserve(addresses.size());
    host_candidates.reserve(addresses.size());
    for (const auto &address : addresses) {
        if ((!this->_config.use_ipv6 && address.is_v6()) ||
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
        host_transports.push_back(transport);
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
        co_return result;

    std::vector<ice::candidate> srflx_candidates;

    if (!this->_config.stun_servers.empty()) {
        exec::async_scope scope;
        net::steady_timer timer(this->_ctx, timeout);
        co_await stdexec::when_all(
            this->server_reflexive_candidate(scope, srflx_candidates,
                                             host_candidates, stun_client,
                                             this->_config.stun_servers),
            timer.async_wait(asio2exec::use_sender) |
                stdexec::then([&scope](auto ec) {
                    ICE_IN_DEBUG {
                        std::cout << "get_component_candidates timeout\n";
                    }
                    scope.request_stop();
                }) |
                stdexec::upon_stopped([&scope] {
                    ICE_IN_DEBUG {
                        std::cout << "get_component_candidates canceled\n";
                    }
                    scope.request_stop();
                }));
        co_await scope.on_empty();
    }

    result.append_range(host_candidates);
    result.append_range(srflx_candidates);
    co_return result;
}

} // namespace ice::impl