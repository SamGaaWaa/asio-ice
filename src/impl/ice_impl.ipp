namespace ice {

template <class Endpoint, class Duration = std::chrono::milliseconds>
inline ice::task<std::optional<endpoint>>
server_reflexive_endpoint(auto &client, Endpoint stun_server,
                          Duration timeout) noexcept try {
    stun::message req;
    req.cls = stun::class_t::STUN_CLASS_REQUEST;
    req.method = stun::method_t::STUN_METHOD_BINDING;
    req.fill_random_transaction_id();

    stun::message resp;
    Endpoint from;
    auto result = co_await (client.request(stun_server, req, from, resp, 7) |
                            stdexec::stopped_as_optional());
    if (!result)
        co_return std::nullopt;
    if (from != stun_server) {
        ICE_IN_DEBUG {
            std::cerr << "server_reflexive_candidate: from != stun_server\n";
        }
        co_return std::nullopt;
    }
    ice::endpoint ep;
    if (resp.xor_mapped_address)
        ep = *resp.xor_mapped_address;
    else if (resp.mapped_address)
        ep = *resp.mapped_address;
    else
        co_return std::nullopt;
    co_return ep;
} catch (std::exception &e) {
    ICE_IN_DEBUG {
        std::cerr << "server_reflexive_candidate: " << e.what() << "\n";
    }
    co_return std::nullopt;
}

template <class Endpoint, class Duration = std::chrono::milliseconds>
inline ice::task<std::optional<endpoint>>
server_reflexive_endpoint(auto &client, std::string_view stun_server, Duration timeout) noexcept try {
    net::ip::basic_resolver<typename Endpoint::protocol_type> resolver(client.context());
} catch (std::exception &e) {
    ICE_IN_DEBUG{ std::cerr << e.what() << '\n'; }
    co_return std::nullopt;
}

template <class Layer>
ice::task<std::vector<std::pair<raw_transport_ptr, ice::candidate>>>
datagram_impl<Layer>::get_component_candidates(
    uint8_t component,
    const std::vector<net::ip::address>& addresses,
    std::chrono::milliseconds timeout)
{
    using Self = datagram_impl<Layer>;
    std::vector<std::pair<Self::raw_transport_ptr, ice::candidate>> result;

    if (!addresses.empty()) {
        std::sort(addresses.begin(), addresses.end());
        auto it = std::unique(addresses.begin(), addresses.end());
        addresses.erase(it, addresses.end());
    }
    if (addresses.empty()) {
        return result;
    }

    std::vector<Self::raw_transport_ptr> host_transports;
    host_transports.reserve(addresses.size());
    for (const auto& address : addresses) {
        Layer sock(this->_ctx);
        if (address.is_v4()) {
            sock.open(net::ip::udp::v4());
        } else {
            sock.open(net::ip::udp::v6());
        }
#if ASIOICE_USE_BOOST_ASIO
        boost::system::error_code ec;
#else
        std::error_code ec;
#endif
        // TODO: support port ranges
        sock.bind(Self::endpoint_type(address, 0), ec);
        if (ec) {
            ICE_IN_DEBUG{ std::cerr << "Failed to bind socket: " << ec.message() << '\n'; }
            continue;
        }

        auto transport = std::make_shared<Self::raw_transport>(this->_ctx, std::move(sock));
        host_transports.push_back(transport);

        result.emplace_back(std::move(transport), ice::candidate{
            .foundation = candidate_foundation(candidate_type::host, this->_config.transport, address),
            .component = component,
            .transport = this->_config.transport,
            .priority = candidate_priority(component, candidate_type::host),
            .endpoint = ice::endpoint{address, transport->local_endpoint().port()},
            .type = candidate_type::host
        });
    }
    this->_sockets.append_range(host_transports);

    exec::async_scope scope;

    for (const std::string& stun_server: this->_config.stun_servers) {

    }
}

} // namespace ice