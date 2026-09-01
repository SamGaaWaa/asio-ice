namespace asioice::ssl::impl {

// ---------------------------------------------------------------------------
// helper: hash_algorithm -> OpenSSL EVP_MD
// ---------------------------------------------------------------------------

static inline const ::EVP_MD *
evp_md_from_hash_algo(hash_algorithm algo) noexcept {
    switch (algo) {
    case hash_algorithm::sha1:
        return ::EVP_sha1();
    case hash_algorithm::sha256:
        return ::EVP_sha256();
    case hash_algorithm::sha384:
        return ::EVP_sha384();
    case hash_algorithm::sha512:
        return ::EVP_sha512();
    }
    return ::EVP_sha256();
}

// ---------------------------------------------------------------------------
// operation structs
// ---------------------------------------------------------------------------

template <class NextLayer> struct dtls_impl<NextLayer>::send_op {
    template <class ConstBufferSequence>
    send_op(const ConstBufferSequence &buf, dtls_impl<NextLayer> *impl) noexcept
        : _buf_seq{buf}, _impl{impl} {}

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
                _buf_seq.buffers().front() = net::const_buffer{
                    _impl->_gather_buf.data(), _impl->_gather_buf.size()};
            }
            if (_buf_seq.buffers().front().size() == 0) {
                _success = true;
                return;
            }
        }
        _ret = ::SSL_write(_impl->_ssl, _buf_seq.buffers().front().data(),
                           _buf_seq.buffers().front().size());
        if (_ret > 0) {
            _success = true;
            return;
        }
        _err = ::SSL_get_error(_impl->_ssl, _ret);
    }

  private:
    asioice::buffer_wrapper _buf_seq;
    dtls_impl<NextLayer> *_impl;
    bool _first_call = true;
    int _ret = 0;
    int _err = 0;
    bool _success = false;
};

template <class NextLayer> struct dtls_impl<NextLayer>::read_op {
    read_op(net::mutable_buffer buf, dtls_impl<NextLayer> *impl) noexcept
        : _buf{buf}, _impl{impl} {}

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

template <class NextLayer> struct dtls_impl<NextLayer>::retransmission_op {
    retransmission_op(dtls_impl<NextLayer> *impl) noexcept : _impl{impl} {}

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

template <class NextLayer> struct dtls_impl<NextLayer>::handshake_op {
    handshake_op(bool is_client, dtls_impl<NextLayer> *impl) noexcept
        : _is_client{is_client}, _impl{impl} {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        _ret =
            _is_client ? ::SSL_connect(_impl->_ssl) : ::SSL_accept(_impl->_ssl);
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

template <class NextLayer> struct dtls_impl<NextLayer>::shutdown_op {
    shutdown_op(bool fast_shutdown, dtls_impl<NextLayer> *impl) noexcept
        : _fast_shutdown{fast_shutdown}, _impl{impl} {}

    bool success() const noexcept { return _success; }
    int result() const noexcept { return _ret; }
    int error() const noexcept { return _err; }

    void operator()() noexcept {
        assert(!_success);
        unsigned char buf[1200];
        while (::SSL_read(_impl->_ssl, buf, sizeof(buf)) > 0) {
        }
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

// ---------------------------------------------------------------------------
// async_send / async_receive / async_handshake / async_shutdown
// ---------------------------------------------------------------------------

template <class NextLayer>
template <class ConstBufferSequence>
auto dtls_impl<NextLayer>::async_send(const ConstBufferSequence &buf,
                                      auto... self) {
    return this->perform(dtls_impl<NextLayer>::send_op{buf, this});
}

template <class NextLayer>
template <class MutableBufferSequence>
auto dtls_impl<NextLayer>::async_receive(const MutableBufferSequence &buf_seq,
                                         auto... self) {
    net::mutable_buffer buf = *net::buffer_sequence_begin(buf_seq);
    return this->perform(dtls_impl<NextLayer>::read_op{buf, this});
}

template <class NextLayer>
template <class... Args>
auto dtls_impl<NextLayer>::async_handshake(
    dtls_impl<NextLayer>::handshake_type type, Args &&...self) {
    return this->perform(dtls_impl<NextLayer>::handshake_op{
               type == dtls_impl<NextLayer>::handshake_type::client, this}) |
           stdexec::then([](std::tuple<std::error_code, std::size_t> ret) {
               return std::get<0>(ret);
           });
}

template <class NextLayer>
template <class... Args>
auto dtls_impl<NextLayer>::async_shutdown(bool fast_shutdown, Args &&...self) {
    return this->perform(
               dtls_impl<NextLayer>::shutdown_op{fast_shutdown, this}) |
           stdexec::then([this](std::tuple<std::error_code, std::size_t> ret) {
               if (std::get<0>(ret) == std::error_code{})
                   this->_closed = true;
               return std::get<0>(ret);
           });
}

// ---------------------------------------------------------------------------
// timeout handling
// ---------------------------------------------------------------------------

template <class NextLayer> void dtls_impl<NextLayer>::handle_timeout() {
    if (!this->_timeout_handler_promise.empty() || this->_closed)
        return;
    ::timeval tv;
    if (!::DTLSv1_get_timeout(this->_ssl, &tv))
        return;
    (void)tv;
    utils::detached_with_data(
        utils::stop_when(this->timeout_handler(),
                         this->_timeout_handler_promise.get_future()),
        this->shared_from_this());
}

template <class NextLayer>
asioice::task<void> dtls_impl<NextLayer>::timeout_handler() {
    if (this->_closed)
        co_return;
    typename dtls_impl<NextLayer>::timer_type timer{this->get_executor()};
    while (true) {
        ::timeval tv;
        std::chrono::milliseconds timeout;
        if (!::DTLSv1_get_timeout(this->_ssl, &tv)) {
            // error or no timeout
            co_return;
        } else {
            timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::seconds(tv.tv_sec) +
                std::chrono::microseconds(tv.tv_usec));
        }
        if (timeout > std::chrono::milliseconds{1}) {
            timer.expires_after(timeout);
            co_await timer.async_wait(utils::use_sender);
        }
        co_await this->perform(dtls_impl<NextLayer>::retransmission_op{this});
    }
}

// ---------------------------------------------------------------------------
// perform (main I/O loop)
// ---------------------------------------------------------------------------

template <class NextLayer>
template <OpenSSLOperation Op>
stdexec::task<std::tuple<std::error_code, std::size_t>, ::asioice::task_env>
dtls_impl<NextLayer>::perform(std::allocator_arg_t, auto alloc, dtls_impl *self,
                              Op op) {
    auto ssl_lk = co_await self->_ssl_mutex.lock();
    assert(self->_bio.out.empty());

    ::ERR_clear_error();
    self->_bio.last_io_failed(false);
    utils::scope_guard on_exit(
        [&]() noexcept { assert(op.error() != SSL_ERROR_WANT_WRITE); });
    while (true) {
        self->handle_timeout();
        if (!ssl_lk)
            ssl_lk = co_await self->_ssl_mutex.lock();
        utils::scope_guard clear_out_guard(
            [self]() noexcept { self->_bio.out.clear(); });
        op();
        if (!self->_bio.out.empty()) {
            utils::scope_guard reset_guard{[&]() noexcept {
                if (op.success() || op.error() != SSL_ERROR_WANT_WRITE)
                    return;
                // reset the SSL state
                self->_bio.last_io_failed(true);
                op();
            }};
            while (!self->_bio.out.empty()) {
                auto packet = self->_bio.out.peek();
                auto [ec, n] = co_await self->next_layer().async_send(packet);
                if (ec) {
                    SAMLOG_WARN(auto sink) {
                        sink("next_layer().async_send_to failed: {}\n",
                             ec.message());
                    };
                    co_return std::make_tuple(ec, 0);
                }
                if (n < packet.size()) {
                    SAMLOG_WARN(auto sink) {
                        sink("dtls_impl::async_send: short write drop {} "
                             "bytes\n",
                             packet.size() - n);
                    };
                }
                self->_bio.out.pop();
            }
            reset_guard.dismiss();
        }
        if (op.success())
            co_return std::make_tuple(std::error_code{},
                                      static_cast<std::size_t>(op.result()));
        int err = op.error();
        switch (err) {
        case SSL_ERROR_WANT_READ:
            break;
        case SSL_ERROR_WANT_WRITE:
            continue;
        case SSL_ERROR_SSL:
            SAMLOG_WARN(auto sink) { sink("perform error: SSL_ERROR_SSL\n"); };
            co_return std::make_tuple(
                std::make_error_code(std::errc::protocol_error), 0);
        case SSL_ERROR_ZERO_RETURN:
            SAMLOG_INFO(auto sink) { sink("DTLS connection closed\n"); };
            self->_peer_closed = true;
            co_return std::make_tuple(std::error_code{}, 0);
        default:
            SAMLOG_WARN(auto sink) { sink("perform error: {}\n", err); };
            co_return std::make_tuple(std::make_error_code(std::errc::io_error),
                                      0);
        }
        self->_bio.out.clear();
        clear_out_guard.dismiss();

        ssl_lk.unlock();
        while (self->_bio.in.empty()) {
            co_await self->_bio.in.wait();
        }
    }
    std::unreachable();
}

template <class NextLayer>
template <OpenSSLOperation Op>
auto dtls_impl<NextLayer>::perform(Op op) {
    return ::asioice::utils::with_allocator(
        [op = std::move(op), this](auto alloc) mutable {
            return perform(std::allocator_arg, std::move(alloc), this,
                           std::move(op));
        },
        std::pmr::polymorphic_allocator<std::byte>{});
}

// ---------------------------------------------------------------------------
// datagram dispatch
// ---------------------------------------------------------------------------

template <class NextLayer>
bool dtls_impl<NextLayer>::datagram_received(io_buffer_ptr &buffer,
                                             const asioice::endpoint &) {
    if (!buffer) {
        this->close();
        return false;
    }
    if (buffer->size() < 1)
        return false;
    uint8_t first_b = *buffer->begin();
    if (first_b < 20 || first_b > 63)
        return false;
    auto buf = std::move(buffer);
    this->_bio.in.push(std::move(buf));
    return true;
}

template <class NextLayer>
bool dtls_impl<NextLayer>::datagram_received(io_buffer_ptr &buffer) {
    if (!buffer) {
        this->close();
        return false;
    }
    if (buffer->size() < 1)
        return false;
    uint8_t first_b = *buffer->begin();
    if (first_b < 20 || first_b > 63)
        return false;
    auto buf = std::move(buffer);
    this->_bio.in.push(std::move(buf));
    return true;
}

template <class NextLayer> void dtls_impl<NextLayer>::close() noexcept {
    this->_timeout_handler_promise.set_stopped();
    if (this->_closed)
        return;
    this->_closed = true;
    utils::detached_with_data(this->async_shutdown(true),
                              this->shared_from_this());
}

// ---------------------------------------------------------------------------
// fingerprint verification
// ---------------------------------------------------------------------------

template <class NextLayer>
int dtls_impl<NextLayer>::verify_callback(int preverify_ok,
                                          X509_STORE_CTX *ctx) {
    ::SSL *ssl = static_cast<::SSL *>(
        X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    auto *self = static_cast<dtls_impl *>(::SSL_get_ex_data(ssl, 0));
    if (!self || self->_expected_remote_fingerprint.empty())
        return preverify_ok;

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert)
        return 0;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    const hash_algorithm algo = self->_expected_remote_fingerprint.algorithm;
    if (!::X509_digest(cert, evp_md_from_hash_algo(algo), md, &n))
        return 0;
    std::string hex_str = utils::dot_hex(md, n);
    return (hex_str == self->_expected_remote_fingerprint.value) ? 1 : 0;
}

template <class NextLayer>
void dtls_impl<NextLayer>::set_expected_remote_fingerprint(
    fingerprint fp) noexcept {
    _expected_remote_fingerprint = fp;
    std::transform(_expected_remote_fingerprint.value.begin(),
                   _expected_remote_fingerprint.value.end(),
                   _expected_remote_fingerprint.value.begin(),
                   [](unsigned char c) { return std::toupper(c); });
}

template <class NextLayer>
fingerprint
dtls_impl<NextLayer>::get_remote_fingerprint(hash_algorithm algo) const {
    ::X509 *peer_cert = ::SSL_get_peer_certificate(_ssl);
    if (!peer_cert)
        return fingerprint{algo, ""};
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    bool ok = ::X509_digest(peer_cert, evp_md_from_hash_algo(algo), md, &n);
    ::X509_free(peer_cert);
    if (!ok)
        return fingerprint{algo, ""};
    std::string hex_str = utils::dot_hex(md, n);
    return fingerprint{algo, std::move(hex_str)};
}

// ---------------------------------------------------------------------------
// SRTP key material
// ---------------------------------------------------------------------------

template <class NextLayer>
std::optional<srtp_key_material>
dtls_impl<NextLayer>::export_srtp_key_material() {
    srtp_key_material keys;

    ::SRTP_PROTECTION_PROFILE *profile = ::SSL_get_selected_srtp_profile(_ssl);
    if (!profile)
        return {};

    std::string profile_name(profile->name);
    if (profile_name == "SRTP_AES128_CM_SHA1_80")
        keys.profile = srtp_protection_profile::srtp_aes128_cm_sha1_80;
    else if (profile_name == "SRTP_AES128_CM_SHA1_32")
        keys.profile = srtp_protection_profile::srtp_aes128_cm_sha1_32;
    else if (profile_name == "SRTP_AEAD_AES_128_GCM")
        keys.profile = srtp_protection_profile::srtp_aead_aes_128_gcm;
    else if (profile_name == "SRTP_AEAD_AES_256_GCM")
        keys.profile = srtp_protection_profile::srtp_aead_aes_256_gcm;
    else
        return {};

    size_t key_len = 16;
    size_t salt_len = 14;
    if (keys.profile == srtp_protection_profile::srtp_aead_aes_256_gcm) {
        key_len = 32;
        salt_len = 12;
    } else if (keys.profile == srtp_protection_profile::srtp_aead_aes_128_gcm) {
        key_len = 16;
        salt_len = 12;
    }

    size_t material_len = (key_len + salt_len) * 2;
    std::vector<uint8_t> material(material_len);

    int ret =
        ::SSL_export_keying_material(_ssl, material.data(), material_len,
                                     "EXTRACTOR-dtls_srtp", 19, nullptr, 0, 0);
    if (ret != 1)
        return {};

    const uint8_t *p = material.data();
    keys.client_write_key.assign(p, p + key_len);
    p += key_len;
    keys.server_write_key.assign(p, p + key_len);
    p += key_len;
    keys.client_write_salt.assign(p, p + salt_len);
    p += salt_len;
    keys.server_write_salt.assign(p, p + salt_len);

    return keys;
}

} // namespace asioice::ssl::impl
