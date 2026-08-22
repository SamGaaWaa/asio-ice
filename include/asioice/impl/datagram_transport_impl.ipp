namespace asioice::impl {

template <class Socket> void datagram_transport_impl<Socket>::start() {
    using Self = datagram_transport_impl<Socket>;
    if (this->_running)
        return;
    utils::detached_with_data(
        stdexec::starts_on(
            utils::basic_scheduler<typename Self::executor_type>{
                this->get_executor()},
            utils::stop_when(
                this->recv_loop(),
                this->_stop.get_future() |
                    stdexec::continues_on(
                        utils::basic_scheduler<typename Self::executor_type>{
                            this->get_executor()}))),
        this->shared_from_this());
    this->_running = true;
}

template <class Socket>
asioice::task<void> datagram_transport_impl<Socket>::recv_loop() {
    utils::scope_guard on_exit([this]() noexcept { this->_running = false; });
    while (true) {
        io_buffer_ptr buf(this->_pool.get(), 0, 4096);
        assert(buf->capacity() == 4096);
        typename datagram_transport_impl<Socket>::endpoint_type ep;
        if constexpr (requires {
                          this->socket().async_receive_from(
                              buf->prepare_back(buf->capacity()), ep,
                              utils::use_sender);
                      }) {
            auto [ec, n] = co_await this->socket().async_receive_from(
                buf->prepare_back(buf->capacity()), ep, utils::use_sender);
            if (ec) {
                SAMLOG_WARN(auto sink) {
                    sink("recv_loop: {}\n", ec.message());
                };
                co_return;
            }
            if (n == 0)
                co_return;
            buf->commit_back(n);
        } else {
            auto [ec, n] = co_await this->socket().async_receive(
                buf->prepare_back(buf->capacity()), utils::use_sender);
            if (ec) {
                SAMLOG_WARN(auto sink) {
                    sink("recv_loop: {}\n", ec.message());
                };
                co_return;
            }
            if (n == 0)
                co_return;
            buf->commit_back(n);
        }
        if (!dispatch_receivers(this->receivers(), buf, ep) &&
            !this->_stop_cache_early_data) {
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
void datagram_transport_impl<Socket>::add_receiver(
    datagram_receiver &receiver) noexcept {
    this->_early_data.dispatch_receiver(receiver);
    this->receivers().push_back(receiver);
}

} // namespace asioice::impl