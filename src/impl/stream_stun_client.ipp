#include "asio2exec.hpp"
#include "scope_guard.hpp"
#include "stop_when.hpp"
#include <algorithm>
#include <boost/container/small_vector.hpp>
#include <cassert>
#include <ranges>

namespace ice::stun::impl {

template <class NextLayer> void stream_client<NextLayer>::stop() noexcept {
    if (!this->_running)
        return;
    this->_running = false;
    this->_stop_promise.set_value();
}

template <class NextLayer>
bool stream_client<NextLayer>::dispatch(const void *data,
                                        std::size_t size) noexcept {
    if (!this->_running)
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
        it->response.reset();
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
        // If the request was sent over a reliable transport, the response MUST
        // be discarded, and the layer MUST immediately end the transaction and
        // signal that the integrity protection was violated
        ICE_IN_DEBUG { std::cout << "Integrity protection was violated\n"; }
        it->success = false;
    } else
        it->success = true;
    it->unlink();
    it->done_promise.set_value();
    return true;
}

template <class NextLayer>
ice::task<bool> stream_client<NextLayer>::request(const stun::message &msg,
                                                  stun::message &resp,
                                                  auto... self) {
    if (!this->_running)
        co_return false;
    auto it = this->_transactions.lower_bound(msg.transaction_id);
    if (it != this->_transactions.end() &&
        it->request.transaction_id == msg.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return false;
    }
    transaction trans{.request{msg}, .response{resp}};
    this->_transactions.insert(it, trans);
    utils::scope_guard on_exit([&]() noexcept {
        if (trans.is_linked())
            trans.unlink();
    });

    boost::container::small_vector<std::byte, 1024> buf;
    buf.resize(msg.serialized_size());
    {
        auto n = msg.write_to(buf.data(), buf.size());
        if (n < 0) {
            ICE_IN_DEBUG { std::cerr << "USERNAME, NONCE or REALM too long\n"; }
            co_return false;
        }
        buf.resize(n);
    }

    std::optional<std::tuple<std::error_code, std::size_t>> result =
        co_await utils::stop_when(
            net::async_write(this->next_layer(),
                             net::buffer(buf.data(), buf.size()),
                             asio2exec::use_sender),
            this->_stop_promise.get_future());
    if (!result) {
        ICE_IN_DEBUG { std::cerr << "Timeout or canceled\n"; }
        co_return false;
    }
    auto [err, nwrite] = *result;
    if (err) {
        ICE_IN_DEBUG {
            std::cerr << "Send request failed:" << err.message() << '\n';
        }
        co_return false;
    }
    if (trans.success)
        co_return true;
    std::optional<bool> success = co_await utils::stop_when(
        trans.done_promise.get_future() |
            stdexec::then([&] { return trans.success; }),
        this->_stop_promise.get_future());
    if (!success) {
        ICE_IN_DEBUG { std::cerr << "Request canceled\n"; }
        co_return false;
    }
    co_return *success;
}

} // namespace ice::stun::impl