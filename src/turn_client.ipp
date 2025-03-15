

namespace ice::turn {

template <is_datagram_layer NextLayer> void client<NextLayer>::stop() noexcept {
    this->_stun_client->stop();
}

template <is_datagram_layer NextLayer>
bool client<NextLayer>::dispatch(std::unique_ptr<stun::message> msg) {
    if (msg->is_response()) {
        return this->_stun_client->dispatch(this->_server, std::move(msg));
    }
    return false;
}

template <is_datagram_layer NextLayer>
ice::task<std::unique_ptr<stun::message>>
client<NextLayer>::request(const stun::message &msg, auto timeout,
                           std::size_t retries) {
    auto [resp, ep] = co_await this->_stun_client->request(this->_server, msg,
                                                           timeout, retries);
    assert(ep == this->_server);
    co_return std::move(resp);
}

template <is_stream_layer NextLayer>
ice::task<std::unique_ptr<stun::message>>
client<NextLayer>::request(const stun::message &msg, auto timeout) {
    co_return co_await this->_stun_client->request(msg, timeout);
}

} // namespace ice::turn