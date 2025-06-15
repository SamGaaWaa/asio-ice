namespace ice::stun::impl {

template <class LowestLayer>
void datagram_client<LowestLayer>::stop() noexcept {
    this->_stop_promise.set_value();
}

template <class LowestLayer>
bool datagram_client<LowestLayer>::dispatch_response(
    const typename datagram_client<LowestLayer>::endpoint_type &ep,
    const void *data, std::size_t size) noexcept {
    if (!this->is_running())
        return false;
    if (message::is_not_stun(data, size) || !message::is_response(data, size))
        return false;
    std::array<uint8_t, 12> transaction_id{};
    std::copy_n(message::get_transaction_id(data, size), 12,
                transaction_id.data());

    auto it = this->_transactions.find(transaction_id);
    if (it == this->_transactions.end()) {
        ICE_IN_DEBUG { std::cout << "Unknown transaction id\n"; }
        // TODO: May be an application message
        return false;
    }
    it->response.reset();
    if (!it->response.parse(data, size)) {
        ICE_IN_DEBUG { std::cerr << "Parse response failed\n"; }
        return false;
    }
    if (it->response.cls == stun::class_t::STUN_CLASS_RESP_ERROR &&
        !it->response.error_code.has_value()) {
        // If the error response contains unknown comprehension-required
        // attributes, or if the error response does not contain an ERROR-CODE
        // attribute, then the transaction is simply considered to have failed.
        it->success = false;
    } else if (it->response.cls == stun::class_t::STUN_CLASS_RESP_ERROR &&
               (it->response.error_code->code == 401 ||
                it->response.error_code->code == 438)) {
        it->success = true;
    } else if (!it->response.nonce.empty() && !it->response.realm.empty() &&
               it->response.nonce.starts_with(stun::STUN_NONCE_COOKIE) &&
               (it->response.security_features() & 0x01) &&
               it->response.pwd_algorithms.empty()) {
        // For all other responses, if the NONCE attribute starts with the
        // "nonce cookie" with the STUN Security Feature "Password algorithms"
        // bit set to 1 but PASSWORD-ALGORITHMS is not present, the response
        // MUST be ignored.
        return true;
    } else if (!it->request.hmac_key().empty() &&
               std::any_of(it->response.integrities.begin(),
                           it->response.integrities.end(), [&](const auto i) {
                               return !i.verify(it->request.hmac_key(),
                                                it->response);
                           })) {
        // If the request was sent over an unreliable transport, the response
        // MUST be discarded, as if it had never been received.  This means that
        // retransmits, if applicable, will continue.  If all the responses
        // received are discarded, then instead of signaling a timeout after
        // ending the transaction, the layer MUST signal that the integrity
        // protection was violated.
        ICE_IN_DEBUG { std::cout << "Discard invalid response\n"; }
        return true;
    } else
        it->success = true;
    it->response_from = ep;
    it->unlink();
    it->done_promise.set_value();
    return true;
}

template <class LowestLayer>
template <class Transport>
ice::task<bool> datagram_client<LowestLayer>::request(
    Transport &transport,
    const typename datagram_client<LowestLayer>::endpoint_type &ep,
    const stun::message &msg,
    typename datagram_client<LowestLayer>::endpoint_type &from,
    stun::message &resp, std::size_t max_retries, auto... self) {
    ice::shared_promise<void> stop_receiver, stop_retry;
    auto retry_coro = [&, this]() -> ice::task<bool> {
        std::chrono::milliseconds retry_rto(500);
        boost::container::small_vector<std::byte, 1024> buf;
        net::steady_timer timer{this->context()};

        utils::scope_guard on_err(
            [&]() noexcept { stop_receiver.set_stopped(); });

        buf.resize(msg.serialized_size());
        {
            auto n = msg.write_to(buf.data(), buf.size());
            if (n < 0) {
                ICE_IN_DEBUG {
                    std::cerr << "USERNAME, NONCE or REALM too long\n";
                }
                co_return false;
            }
            buf.resize(n);
        }
        for (int i = 0; i < max_retries; ++i) {
            auto [err, n] = co_await transport.template async_send_to(
                net::buffer(buf.data(), buf.size()), ep, asio2exec::use_sender);
            if (err) {
                ICE_IN_DEBUG {
                    std::cerr << "STUN transaction failed: " << err.message()
                              << "\n";
                }
                co_return false;
            }
            if (n != buf.size()) {
                ICE_IN_DEBUG {
                    std::cerr << "STUN transaction failed: sent " << n
                              << "bytes, expected " << buf.size() << "\n";
                }
                co_return false;
            }
            timer.expires_after(retry_rto);
            retry_rto *= 2;
            err = co_await timer.async_wait(asio2exec::use_sender);
            if (err) {
                ICE_IN_DEBUG {
                    std::cerr << "STUN transaction stopped: " << err.message()
                              << '\n';
                }
                co_return false;
            }
        }
        on_err.dismiss();
        ICE_IN_DEBUG { std::cout << "Retring finished\n"; }
        co_return true;
    };

    auto it = this->_transactions.lower_bound(msg.transaction_id);
    if (it != this->_transactions.end() &&
        it->request.transaction_id == msg.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return false;
    }
    transaction trans{.request{msg}, .response_from{from}, .response{resp}};
    this->_transactions.insert(it, trans);
    utils::scope_guard on_exit([&]() noexcept {
        if (trans.is_linked())
            trans.unlink();
    });

    auto recv_work = trans.done_promise.get_future() | stdexec::then([&] {
                         stop_retry.set_stopped();
                         return trans.success;
                     }) |
                     stdexec::upon_error([&](std::exception_ptr err) {
                         stop_retry.set_stopped();
                         return false;
                     }) |
                     stdexec::upon_stopped([&] {
                         stop_retry.set_stopped();
                         return false;
                     });

    std::optional<std::tuple<std::optional<bool>, std::optional<bool>>> result =
        co_await (utils::stop_when(
            stdexec::when_all(
                utils::stop_when(retry_coro(), stop_retry.get_future()),
                utils::stop_when(std::move(recv_work),
                                 stop_receiver.get_future())),
            this->_stop_promise.get_future()));

    if (!result) {
        ICE_IN_DEBUG { std::cerr << "Canceled\n"; }
        co_return false;
    }
    auto success = std::get<1>(*result);
    assert(success.has_value());
    co_return *success;
}

} // namespace ice::stun::impl