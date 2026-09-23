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
    utils::detached_with_data(
        stdexec::starts_on(
            utils::basic_scheduler<typename Self::executor_type>{
                this->get_executor()},
            utils::stop_when(
                this->send_loop(),
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
        io_buffer_ptr buf(nullptr, 0, 1500);
        assert(buf->capacity() == 1500);
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

constexpr bool asio_uses_epoll() {
#if ASIOICE_USE_BOOST_ASIO
#if defined(BOOST_ASIO_HAS_IO_URING_AS_DEFAULT) ||                             \
    (defined(BOOST_ASIO_HAS_IO_URING) && defined(BOOST_ASIO_DISABLE_EPOLL))
    return false;
#else
    return true;
#endif
#else
#if defined(ASIO_HAS_IO_URING_AS_DEFAULT) ||                                   \
    (defined(ASIO_HAS_IO_URING) && defined(ASIO_DISABLE_EPOLL))
    return false;
#else
    return true;
#endif
#endif
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

template <class Socket>
std::error_code datagram_transport_impl<Socket>::do_sendmmsg(
    typename ::asioice::transport_base::send_op_queue::value_type
        &op_q) noexcept {
#if defined(__linux) || defined(__linux__) || defined(linux)
    constexpr std::size_t max_batch_count = 32;
    using op_type = typename ::asioice::transport_base::send_op_queue::
        value_type::value_type;
    boost::container::small_vector<::iovec, max_batch_count> bufs;
    std::array<::mmsghdr, max_batch_count> msgs{};
    while (!op_q.empty()) {
        bufs.clear();
        std::size_t i = 0;
        for (const auto &op : op_q) {
            if (i++ >= max_batch_count)
                break;
            auto buffers = op.get_buffers();
            for (const auto &buf : buffers)
                bufs.emplace_back((void *)(uint64_t)buf.data(), buf.size());
        }

        std::size_t buf_idx = 0;
        i = 0;
        for (const auto &op : op_q) {
            if (i >= max_batch_count)
                break;
            auto buffers = op.get_buffers();
            const auto &ep = op.get_endpoint();
            auto &hdr = msgs[i++].msg_hdr;
            hdr.msg_name = (void *)(uint64_t)ep.data();
            hdr.msg_namelen = ep.size();
            hdr.msg_iov = &bufs[buf_idx];
            hdr.msg_iovlen = buffers.size();
            buf_idx += buffers.size();
        }

        const auto msg_count = i;
        while (true) {
            int ret = ::sendmmsg(this->_sock.native_handle(), msgs.data(),
                                 msg_count, 0);
            if (ret == -1) {
                if (errno == EINTR)
                    continue;
                return std::error_code{errno, std::generic_category()};
            }

            std::array<op_type *, max_batch_count> ops{};
            for (int i = 0; i < ret; ++i) {
                auto &op = op_q.front();
                op_q.pop_front();
                ops[i] = &op;
            }
            for (int i = 0; i < ret; ++i) {
                ops[i]->set_value(std::error_code{},
                                  std::size_t{msgs[i].msg_len});
            }
            break;
        }
    }
#endif
    return {};
}

template <class Socket>
asioice::task<void> datagram_transport_impl<Socket>::send_loop() {
    using self_type = datagram_transport_impl<Socket>;
    using queue_type =
        typename ::asioice::transport_base::send_op_queue::value_type;

    auto token = co_await stdexec::get_stop_token();
    auto &op_q = this->operation_queue();
    queue_type local_q;

    utils::scope_guard on_stopped{[&]() noexcept {
        op_q.get_operations(local_q);
        while (!local_q.empty()) {
            auto &op = local_q.front();
            local_q.pop_front();
            op.set_stopped();
        }
    }};

    while (_running) {
        if (local_q.empty()) {
            op_q.get_operations(local_q);
            if (local_q.empty()) {
                co_await op_q.wait();
                continue;
            }
        }
#if defined(__linux) || defined(__linux__) || defined(linux)
        if (asio_uses_epoll() && local_q.size() > 1) {
            auto ec = this->do_sendmmsg(local_q);
            if (ec) {
                if (ec == std::errc::operation_would_block ||
                    ec == std::errc::resource_unavailable_try_again) {
                    auto wait_ec = co_await this->_sock.async_wait(
                        self_type::socket_type::wait_type::wait_write,
                        utils::use_sender);
                    if (wait_ec)
                        co_return;
                    continue;
                }
                SAMLOG_WARN(auto sink) {
                    sink("do_sendmmsg failed: {}\n", ec.message());
                };
                co_return;
            }
            continue;
        }
#endif
        auto &op = local_q.front();
        local_q.pop_front();

        auto buffers = op.get_buffers();
        auto ep = op.get_endpoint();

        std::optional<std::tuple<std::error_code, std::size_t>> res;
        try {
            if (op.stoppable()) {
                res = co_await (
                    stdexec::__stop_when(
                        _sock.async_send_to(buffers, ep, utils::use_sender),
                        op.stop_token()) |
                    stdexec::stopped_as_optional());
            } else {
                res = co_await (
                    _sock.async_send_to(buffers, ep, utils::use_sender) |
                    stdexec::stopped_as_optional());
            }
        } catch (...) {
            op.set_error(std::current_exception());
            continue;
        }
        if (!res) {
            op.set_stopped();
            if (token.stop_requested())
                co_return;
            else
                continue;
        }
        op.set_value(std::get<0>(*res), std::get<1>(*res));
    }
}

} // namespace asioice::impl