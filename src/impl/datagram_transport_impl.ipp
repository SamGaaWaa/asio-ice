namespace ice::impl {

template <class Socket> void datagram_transport_impl<Socket>::start() {
    if (this->_running)
        return;
    asio2exec::scheduler sched{this->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched, utils::stop_when(this->recv_loop(this->shared_from_this()),
                                this->_stop.get_future() |
                                    stdexec::continues_on(sched))));
    this->_running = true;
}

template <class Socket>
ice::task<void> datagram_transport_impl<Socket>::recv_loop(auto self) {
    utils::scope_guard on_exit([this]() noexcept { this->_running = false; });
    while (true) {
        io_buffer_ptr buf(&this->_pool, 64, this->max_buffer_size());
        typename datagram_transport_impl<Socket>::endpoint_type ep;
        auto [ec, n] = co_await this->socket().async_receive_from(
            buf->prepare_back(this->max_buffer_size()), ep,
            asio2exec::use_sender);
        if (ec) {
            ICE_IN_DEBUG { std::cerr << "recv_loop: " << ec.message() << "\n"; }
            co_return;
        }
        if (n == 0)
            co_return;
        buf->commit_back(n);
        if (!dispatch_receivers(this->receivers(), buf, ep) &&
            !this->_stop_cache_early_data)
        {
            this->_early_data.put(buf, ep);
        }
    }
}

template <class Socket>
void datagram_transport_impl<Socket>::clear_early_data() noexcept {
    this->_stop_cache_early_data = true;
    this->_early_data.clear();
}

template <class Socket>
void
datagram_transport_impl<Socket>::add_receiver(datagram_receiver &receiver) noexcept {
    this->_early_data.dispatch_receiver(receiver);
    this->receivers().push_back(receiver);
}

} // namespace ice::impl