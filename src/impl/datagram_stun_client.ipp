#include "asio2exec.hpp"
#include "scope_guard.hpp"
#include "stop_when.hpp"
#include <boost/container/small_vector.hpp>
#include <cassert>

namespace ice::stun::impl {

template <class NextLayer> void datagram_client<NextLayer>::stop() noexcept {
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
bool datagram_client<NextLayer>::dispatch(
    const typename datagram_client<NextLayer>::endpoint_type &ep,
    const void *data, std::size_t size) noexcept {
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
    it->response_from = ep;
    it->success = true;
    // TODO: handle message
    ICE_IN_DEBUG {
        std::cout << "STUN message from " << ep.address() << ":" << ep.port()
                  << ":\n"
                  << it->response.to_string() << "\n";
    }
    it->unlink();
    it->done_promise.set_value();
    return true;
}

template <class NextLayer>
ice::task<bool> datagram_client<NextLayer>::request(
    const typename datagram_client<NextLayer>::endpoint_type &ep,
    const stun::message &msg,
    typename datagram_client<NextLayer>::endpoint_type &from,
    stun::message &resp, auto timeout, std::size_t max_retries) {
    if (!this->_running)
        co_return false;
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
            assert(n != -1);
            buf.resize(n);
        }
        for (int i = 0; i < max_retries; ++i) {
            auto [err, n] = co_await this->next_layer().async_send_to(
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
        it->transaction_id == msg.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        co_return false;
    }
    transaction trans{.transaction_id{msg.transaction_id},
                      .response_from{from},
                      .response{resp}};
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

    net::steady_timer timer{this->context(), timeout};

    std::optional<std::tuple<std::optional<bool>, std::optional<bool>>> result =
        co_await (utils::stop_when(
            stdexec::when_all(
                utils::stop_when(retry_coro(), stop_retry.get_future()),
                utils::stop_when(std::move(recv_work),
                                 stop_receiver.get_future())),
            timer.async_wait(asio2exec::use_sender)));

    if (!result) {
        ICE_IN_DEBUG { std::cerr << "Timeout\n"; }
        co_return false;
    }
    auto success = std::get<1>(*result);
    assert(success.has_value());
    co_return *success;
}

} // namespace ice::stun::impl