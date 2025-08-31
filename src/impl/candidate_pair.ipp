namespace ice {

template <class StunClient>
bool candidate_pair<StunClient>::datagram_received(
    io_buffer_ptr &buffer,
    const typename candidate_pair<StunClient>::endpoint_type &endpoint) {
    if (!buffer) [[unlikely]] // ignore empty buffers
        return true;
    const uint8_t first_byte = *buffer->begin();
    if (first_byte <= 3) [[unlikely]] {
        // STUN
        if (buffer->size() < ice::stun::HEADER_SIZE) {
            // invalid STUN, ignore
            return true;
        }
        auto cls =
            ice::stun::message::get_class(buffer->data(), buffer->size());
        if (cls == stun::class_t::STUN_CLASS_RESP_SUCCESS ||
            cls == stun::class_t::STUN_CLASS_RESP_ERROR) {
            this->stun_client().dispatch_response(
                endpoint, buffer->data(), buffer->size(),
                this->_local_candidate.transport.data());
            return true;
        }
        if (cls == stun::class_t::STUN_CLASS_REQUEST) {
            if (this->_request_handler)
                this->_request_handler(
                    ice::endpoint{endpoint.address(), endpoint.port()},
                    this->_local_candidate.endpoint,
                    std::move(buffer));
            return true;
        }
        // indication, ignore
        return true;
    } else if (first_byte >= 64 && first_byte <= 79) [[unlikely]] {
        // TURN channel, ignore
        return true;
    }
    if (endpoint != this->remote_endpoint())
        return false;
    // application data
    dispatch_receivers(this->receivers(), buffer, endpoint);
    return true;
}

template <class StunClient>
ice::task<bool> candidate_pair<StunClient>::request(const stun::message &req,
                                                    stun::message &res,
                                                    size_t retries) {
    typename candidate_pair<StunClient>::endpoint_type from;
    const void *resp_to = nullptr;
    bool ret = co_await this->stun_client().request(
        this->_local_candidate.transport, this->remote_endpoint(), req, from,
        res, retries, &resp_to);
    if (!ret)
        co_return false;
    if (from != this->remote_endpoint()) {
        ICE_IN_DEBUG {
            std::cerr << "Non-Symmetric Transport Addresses, from: "
                      << from.address() << ':' << from.port() << '\n';
        }
        co_return false;
    }
    if (resp_to != this->_local_candidate.transport.data()) {
        ICE_IN_DEBUG {
            std::cerr << "Non-Symmetric Transport Addresses, to: " << resp_to << '\n';
        }
        co_return false;
    }
    co_return true;
}

} // namespace ice