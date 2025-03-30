#include "asio2exec.hpp"
#include "scope_guard.hpp"
#include "stop_when.hpp"
#include <boost/container/small_vector.hpp>
#include <cassert>

namespace ice::stun::impl {

template <class NextLayer> void stream_client<NextLayer>::stop() noexcept {
    if (!this->_running)
        return;
    this->_running = false;
    while (!this->_transactions.empty()) {
        auto &trans = *_transactions.begin();
        trans.unlink();
        trans.done_promise.set_stopped();
    }
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
    it->success = true;
    // TODO: handle message
    it->unlink();
    it->done_promise.set_value();
    return true;
}

template <class NextLayer>
ice::task<bool> stream_client<NextLayer>::request(const stun::message &msg,
                                                  stun::message &resp,
                                                  auto timeout) {
    if (!this->_running)
        co_return false;
    auto it = this->_transactions.lower_bound(msg.transaction_id);
    if (it != this->_transactions.end() &&
        it->transaction_id == msg.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return false;
    }
    transaction trans{.transaction_id{msg.transaction_id}, .response{resp}};
    this->_transactions.insert(it, trans);
    utils::scope_guard on_exit([&]() noexcept {
        if (trans.is_linked())
            trans.unlink();
    });
    auto deadline = timeout + std::chrono::steady_clock::now();
    boost::container::small_vector<std::byte, 1024> buf;

    buf.resize(msg.serialized_size());
    {
        auto n = msg.write_to(buf.data(), buf.size());
        assert(n != -1);
        buf.resize(n);
    }

    net::steady_timer timer{this->context(), deadline};
    std::optional<std::tuple<std::error_code, std::size_t>> result =
        co_await utils::stop_when(
            net::async_write(this->next_layer(),
                             net::buffer(buf.data(), buf.size()),
                             asio2exec::use_sender),
            timer.async_wait(asio2exec::use_sender));
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
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        ICE_IN_DEBUG { std::cerr << "Request timeout\n"; }
        co_return false;
    }
    timer.expires_at(deadline);
    std::optional<bool> success = co_await utils::stop_when(
        trans.done_promise.get_future() |
            stdexec::then([&] { return trans.success; }),
        timer.async_wait(asio2exec::use_sender));
    if (!success) {
        ICE_IN_DEBUG { std::cerr << "Request timeout\n"; }
        co_return false;
    }
    co_return *success;
}

} // namespace ice::stun::impl