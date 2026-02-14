namespace ice::ssl::impl {

template <class NextLayer>
struct dtls_impl<NextLayer>::send_op
{
    template <class ConstBufferSequence>
    send_op(const ConstBufferSequence& buf, dtls_impl<NextLayer> *impl) noexcept:
        _buf_seq{buf},
        _impl{impl}
    {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        if (_first_call) {
            _first_call = false;
            // prepare
            if (_buf_seq.buffers().empty()) {
                _success = true;
                return;
            }
            if (_buf_seq.buffers().size() > 1) {
                net::buffer_copy(net::buffer(_impl->_gather_buf), _buf_seq);
                _buf_seq.buffers().front() = net::const_buffer{_impl->_gather_buf.data(), _impl->_gather_buf.size()};
            }
            if (_buf_seq.buffers().front().size() == 0) {
                _success = true;
                return;
            }
        }
        _ret = ::SSL_write(_impl->_ssl, _buf_seq.buffers().front().data(), _buf_seq.buffers().front().size());
        if (_ret > 0) {
            _success = true;
            return;
        }
        _err = ::SSL_get_error(_impl->_ssl, _ret);
    }
private:
    ice::buffer_wrapper _buf_seq;
    dtls_impl<NextLayer> *_impl;
    bool _first_call = true;
    int _ret = 0;
    int _err = 0;
    bool _success = false;
};

template <class NextLayer>
struct dtls_impl<NextLayer>::read_op
{
    read_op(net::mutable_buffer buf, dtls_impl<NextLayer> *impl) noexcept:
        _buf{buf},
        _impl{impl}
    {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        if (_buf.size() == 0) {
            _success = true;
            _ret = 0;
            return;
        }
        _ret = ::SSL_read(_impl->_ssl, _buf.data(), _buf.size());
        if (_ret > 0) {
            _success = true;
            return;
        }
        _err = ::SSL_get_error(_impl->_ssl, _ret);
    }
private:
    net::mutable_buffer _buf;
    dtls_impl<NextLayer> *_impl;
    int _ret = 0;
    int _err = 0;
    bool _success = false;
};

template <class NextLayer>
struct dtls_impl<NextLayer>::retransmission_op {
    retransmission_op(dtls_impl<NextLayer> *impl) noexcept:
        _impl{impl}
    {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        _ret = ::DTLSv1_handle_timeout(_impl->_ssl);
        if (_ret >= 0) {
            _success = true;
            return;
        }
        _err = ::SSL_get_error(_impl->_ssl, _ret);
    }
private:
    dtls_impl<NextLayer> *_impl;
    int _ret = 0;
    int _err = 0;
    bool _success = false;
};

template <class NextLayer>
struct dtls_impl<NextLayer>::handshake_op {
    handshake_op(bool is_client, dtls_impl<NextLayer> *impl) noexcept:
        _is_client{is_client},
        _impl{impl}
    {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        _ret = _is_client ? ::SSL_connect(_impl->_ssl) : ::SSL_accept(_impl->_ssl);
        if (_ret > 0) {
            _success = true;
            return;
        }
        _err = ::SSL_get_error(_impl->_ssl, _ret);
    }
private:
    bool _is_client;
    dtls_impl<NextLayer> *_impl;
    int _ret = 0;
    int _err = 0;
    bool _success = false;
};

template <class NextLayer>
struct dtls_impl<NextLayer>::shutdown_op {
    shutdown_op(bool fast_shutdown, dtls_impl<NextLayer> *impl) noexcept:
        _fast_shutdown{fast_shutdown},
        _impl{impl}
    {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        unsigned char buf[1200];
        while (::SSL_read(_impl->_ssl, buf, sizeof(buf)) > 0) {}
        int recv_err = ::SSL_get_error(_impl->_ssl, _ret);
        if (recv_err == SSL_ERROR_ZERO_RETURN)
            _impl->_peer_closed = true;
        _ret = ::SSL_shutdown(_impl->_ssl);
        if (_ret == 1) {
            _success = true;
            return;
        } else if (_ret == 0) {
            if (_fast_shutdown) {
                _success = true;
                _ret = 1;
                _err = 0;
                return;
            }
            _err = SSL_ERROR_WANT_READ;
            return;
        }
        _err = ::SSL_get_error(_impl->_ssl, _ret);
        if (_fast_shutdown && _err == SSL_ERROR_WANT_READ) {
            _success = true;
            _ret = 1;
            _err = 0;
            return;
        }
    }
private:
    bool _fast_shutdown;
    dtls_impl<NextLayer> *_impl;
    int _ret = 0;
    int _err = 0;
    bool _success = false;
};

template <class NextLayer>
template <class ConstBufferSequence>
ice::task<std::tuple<std::error_code, std::size_t>>
dtls_impl<NextLayer>::async_send(const ConstBufferSequence& buf, auto ...self)
{
    return this->perform(dtls_impl<NextLayer>::send_op{buf, this}, std::move(self)...);
}

template <class NextLayer>
template <class MutableBufferSequence>
ice::task<std::tuple<std::error_code, std::size_t>>
dtls_impl<NextLayer>::async_receive(const MutableBufferSequence& buf_seq, auto ...self)
{
    net::mutable_buffer buf = *net::buffer_sequence_begin(buf_seq);
    return this->perform(dtls_impl<NextLayer>::read_op{buf, this}, std::move(self)...);
}

template <class NextLayer>
template <class ...Args>
auto
dtls_impl<NextLayer>::async_handshake(dtls_impl<NextLayer>::handshake_type type, Args&& ...self)
{
    return this->perform(dtls_impl<NextLayer>::handshake_op{type == dtls_impl<NextLayer>::handshake_type::client, this}, std::forward<Args>(self)...)
            | stdexec::then([](std::tuple<std::error_code, std::size_t> ret) {
                return std::get<0>(ret);
            });
}

template <class NextLayer>
template <class ...Args>
auto
dtls_impl<NextLayer>::async_shutdown(bool fast_shutdown, Args&& ...self)
{
    return this->perform(dtls_impl<NextLayer>::shutdown_op{fast_shutdown, this}, std::forward<Args>(self)...)
            | stdexec::then([](std::tuple<std::error_code, std::size_t> ret) {
                return std::get<0>(ret);
            });
}

template <class NextLayer>
void dtls_impl<NextLayer>::handle_timeout() {
    if (this->_handing_timeout || this->_closed)
        return;
    ::timeval tv;
    if (!::DTLSv1_get_timeout(this->_ssl, &tv))
        return;
    (void)tv;
    asio2exec::scheduler sched{this->context()};
    utils::detached_with_data(utils::stop_when(
                                this->timeout_handler(),
                                this->_timeout_handler_promise.get_future()), this->shared_from_this());
}

template <class NextLayer>
ice::task<void>
dtls_impl<NextLayer>::timeout_handler()
{
    if (this->_handing_timeout || this->_closed)
        co_return;
    this->_handing_timeout = true;
    ice::utils::scope_guard on_exit([this]()noexcept {
        this->_handing_timeout = false;
    });
    net::steady_timer timer{this->context()};
    while (true) {
        ::timeval tv;
        std::chrono::milliseconds timeout;
        if (!::DTLSv1_get_timeout(this->_ssl, &tv)) {
            // error or no timeout
            co_return;
        } else {
            timeout = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec));
        }
        if (timeout > std::chrono::milliseconds{1}) {
            timer.expires_after(timeout);
            auto ec = co_await timer.async_wait(asio2exec::use_sender);
            if (ec)
                co_return;
        }
        auto [ec, n] = co_await this->perform(dtls_impl<NextLayer>::retransmission_op{this});
        if (ec)
            co_return;
    }
}

template <class NextLayer>
template <OpenSSLOperation Op>
ice::task<std::tuple<std::error_code, std::size_t>>
dtls_impl<NextLayer>::perform(Op op, auto ...self)
{
    auto ssl_lk = co_await this->_ssl_mutex.lock();
    assert(this->_bio.out.empty());

    ::ERR_clear_error();
    this->_bio.last_io_failed(false);
    utils::scope_guard on_exit([&]() noexcept {
        assert(op.error() != SSL_ERROR_WANT_WRITE);
    });
    while (true) {
        this->handle_timeout();
        if (this->_bio.in.empty() && !this->_recv_q.empty()) {
            this->_bio.in = std::move(this->_recv_q.front());
            this->_recv_q.pop_front();
        }
        if (!ssl_lk)
            ssl_lk = co_await this->_ssl_mutex.lock();
        utils::scope_guard clear_out_guard([this]() noexcept {
            this->_bio.out.clear();
        });
        op();
        if (!this->_bio.out.empty()) {
            utils::scope_guard reset_guard{[&]() noexcept {
                if (op.success() || op.error() != SSL_ERROR_WANT_WRITE)
                    return;
                // reset the SSL state
                this->_bio.last_io_failed(true);
                op();
            }};
            auto [ec, n] = co_await this->next_layer().async_send_to(
                                net::const_buffer{this->_bio.out.data(), this->_bio.out.size()},
                                this->remote_endpoint()
                            );
            if (ec) {
                ICE_IN_DEBUG{ std::cout << "next_layer().async_send_to failed: " << ec.message() << '\n'; }
                co_return std::make_tuple(ec, 0); 
            }
            reset_guard.dismiss();
            ICE_IN_DEBUG {
                if (n < this->_bio.out.size())
                    std::cout << "dtls_impl::async_send: short write drop " << this->_bio.out.size() - n << " bytes\n";
            }
        }
        if (op.success())
            co_return std::make_tuple(std::error_code{}, static_cast<std::size_t>(op.result()));
        int err = op.error();
        switch (err) {
            case SSL_ERROR_WANT_READ:
                break;
            case SSL_ERROR_WANT_WRITE:
                continue;
            case SSL_ERROR_SSL:
                ICE_IN_DEBUG{ std::cout << "perform error: SSL_ERROR_SSL\n"; }
                co_return std::make_tuple(std::make_error_code(std::errc::protocol_error), 0);
            case SSL_ERROR_ZERO_RETURN:
                ICE_IN_DEBUG{ std::cout << "DTLS connection closed\n"; }
                this->_peer_closed = true;
                co_return std::make_tuple(std::error_code{}, 0);
            default:
                ICE_IN_DEBUG{ std::cout << "perform error: " << err << '\n'; }
                co_return std::make_tuple(std::make_error_code(std::errc::io_error), 0);
        }
        this->_bio.out.clear();
        clear_out_guard.dismiss();
        if (!this->_recv_q.empty()) {
            this->_bio.in = std::move(this->_recv_q.front());
            this->_recv_q.pop_front();
            continue;
        }

        ssl_lk.unlock();
        do {
            co_await this->_recv_promise.get_future();
        } while (this->_recv_q.empty());
        if (!this->_bio.in.empty())
            continue;
        this->_bio.in = std::move(this->_recv_q.front());
        this->_recv_q.pop_front();
        continue;
    }
    std::unreachable();
}

template <class NextLayer>
bool
dtls_impl<NextLayer>::datagram_received(io_buffer_ptr &buffer, const ice::endpoint &endpoint)
{
    if (!buffer || endpoint != this->_remote || buffer->size() < 1)
        return false;
    uint8_t first_b = *buffer->begin();
    if (first_b < 20 || first_b > 63)
        return false;
    auto buf = std::move(buffer);
    if (this->_recv_q.size() > this->_max_recv_q_size) {
        ICE_IN_DEBUG{ std::cout << "recv queue is full, ignore the packet\n"; }
        return true;
    }
    this->_recv_q.emplace_back(std::move(buf));
    if (this->_recv_q.size() == 1)
        this->_recv_promise.set_one_value();
    return true;
}

} // namespace ice::ssl::impl