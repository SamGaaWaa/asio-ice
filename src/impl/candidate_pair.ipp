namespace ice {

template <class Transport, class StunClient>
bool
candidate_pair<Transport, StunClient>::datagram_received(
    io_buffer_ptr &buffer,
    const typename candidate_pair<Transport, StunClient>::endpoint_type &endpoint) {
    if (!buffer)
        return false;
    uint8_t first_byte = *buffer->begin();
    if (first_byte <= 3) {
        // STUN
        if (buffer->size() < ice::stun::HEADER_SIZE) {
            // ignore
            return true;
        }
        auto cls =
            ice::stun::message::get_class(buffer->data(), buffer->size());
        if (cls == stun::class_t::STUN_CLASS_RESP_SUCCESS ||
            cls == stun::class_t::STUN_CLASS_RESP_ERROR) {
            this->stun_client().dispatch_response(endpoint, buffer->data(),
                                                  buffer->size());
            return true;
        }
        return false;
    } else if (first_byte >= 64 && first_byte <= 79) {
        // TURN channel
        return false;
    }
    if (endpoint != this->remote_endpoint())
        return false;
    dispatch_receivers(this->receivers(), buffer, endpoint);
    return true;
}

template <class Transport, class StunClient>
ice::task<bool>
candidate_pair<Transport, StunClient>::request(const stun::message& req, stun::message& res, size_t retries) {
    typename candidate_pair<Transport, StunClient>::endpoint_type from;
    bool ret = co_await this->stun_client().request(this->template transport<Transport>(), this->remote_endpoint(), req, from, res, retries);
    if (from != this->remote_endpoint()) {
        ICE_IN_DEBUG{ std::cerr << "STUN request from unexpected endpoint: " << from.address() << ':' << from.port() << '\n'; }
        co_return false;
    }
    co_return ret;
}

template <class Transport, class StunClient>
ice::task<std::tuple<std::error_code, std::size_t>>
candidate_pair<Transport, StunClient>::send(std::span<net::const_buffer> data, std::shared_ptr<void> self) {
    co_return co_await this->template transport<Transport>().async_send_to(data, this->remote_endpoint(), asio2exec::use_sender);
}

template <class Transport, class StunClient>
ice::task<std::tuple<std::error_code, std::size_t>>
candidate_pair<Transport, StunClient>::send(const void *data, std::size_t size, std::shared_ptr<void> self) {
    co_return co_await this->template transport<Transport>().async_send_to(net::const_buffer(data, size), this->remote_endpoint(), asio2exec::use_sender);
}

} // namespace ice