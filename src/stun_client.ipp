#include "asio2exec.hpp"
#include "scope_guard.hpp"
#include "stop_when.hpp"
#include <cassert>
#include <exec/when_any.hpp>
#include <iostream>
#include <stdexcept>

namespace ice::stun {

template <class NextLayer> void client_base<NextLayer>::stop() noexcept {
    if (!_running)
        return;
    _running = false;
    _stop_promise.set_stopped();
}

inline std::unique_ptr<stun::message> get_message(auto &pool) {
    if (pool.empty())
        return std::make_unique<stun::message>();
    auto msg = std::move(pool.front());
    pool.pop_front();
    assert(msg != nullptr);
    msg->reset();
    return msg;
}

template <is_datagram_layer NextLayer>
bool client<NextLayer>::dispatch(
    const typename client<NextLayer>::endpoint_type &ep, const void *data,
    std::size_t size) {
    assert(this->_running);
    if (stun::message::is_not_stun(data, size))
        return false;
    auto msg = get_message(this->message_pool());
    utils::scope_guard on_exit([this, &msg]() noexcept {
        this->message_pool().push_back(std::move(msg));
    });
    if (!msg->parse(data, size) || !msg->is_response())
        return false;
    // TODO: handle message
    ICE_IN_DEBUG {
        std::cout << "STUN message from " << ep.address() << ":" << ep.port()
                  << ":\n"
                  << msg->to_string() << "\n";
    }
    on_exit.dismiss();
    return this->dispatch(ep, std::move(msg));
}

template <is_datagram_layer NextLayer>
bool client<NextLayer>::dispatch(
    const typename client<NextLayer>::endpoint_type &ep,
    std::unique_ptr<stun::message> msg) {
    ICE_IN_DEBUG {
        if (!msg || !msg->is_response()) {
            std::cerr << "Incoming STUN message\n";
            throw std::runtime_error("Invalid STUN message");
        }
    }
    utils::scope_guard on_exit([this, &msg]() noexcept {
        this->message_pool().push_back(std::move(msg));
    });
    auto it = _transactions.find(msg->transaction_id);
    if (it == _transactions.end()) {
        ICE_IN_DEBUG { std::cout << "Unknown transaction id\n"; }
        // TODO: May be a application message
        return false;
    }
    it->response = std::move(msg);
    it->response_from = ep;
    it->set_done();
    on_exit.dismiss();
    return true;
}

template <is_datagram_layer NextLayer>
ice::task<void>
client<NextLayer>::transaction::retry(std::chrono::milliseconds timeout,
                                      std::size_t max_retries,
                                      std::shared_ptr<transaction> self) {
    utils::scope_guard on_exit(
        [this]() noexcept { _done_promise.set_value(); });
    net::steady_timer timer{_client->context()};
    for (std::size_t i = 0; i < max_retries; ++i) {
        auto [err, n] = co_await _client->socket().async_send_to(
            net::buffer(_buf.data(), _buf.size()), this->endpoint,
            asio2exec::use_sender);
        if (err) {
            ICE_IN_DEBUG {
                std::cerr << "STUN transaction failed: " << err.message()
                          << "\n";
            }
            co_return;
        }
        if (n != _buf.size()) {
            ICE_IN_DEBUG {
                std::cerr << "STUN transaction failed: sent " << n
                          << "bytes, expected " << _buf.size() << "\n";
            }
            co_return;
        }
        timer.expires_after(timeout);
        timeout *= 2;
        err = co_await timer.async_wait(asio2exec::use_sender);
        if (err) {
            ICE_IN_DEBUG {
                std::cerr << "STUN transaction stopped: " << err.message()
                          << '\n';
            }
            co_return;
        }
    }
    co_return;
}

template <is_datagram_layer NextLayer>
void client<NextLayer>::transaction::run(std::chrono::milliseconds timeout,
                                         std::size_t max_retries) {
    asio2exec::scheduler sched{_client->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched, stdexec::when_all(
                   retry(timeout, max_retries, this->shared_from_this()),
                   _stop_promise.get_future() | stdexec::continues_on(sched))));
}

template <is_datagram_layer NextLayer>
ice::task<std::tuple<std::unique_ptr<stun::message>,
                     typename client<NextLayer>::endpoint_type>>
client<NextLayer>::request(const typename client<NextLayer>::endpoint_type &ep,
                           const stun::message &msg, auto timeout,
                           std::size_t retries) {
    assert(this->_running);
    auto state = this->_transactions.lower_bound(msg.transaction_id);
    if (state != this->_transactions.end() &&
        state->transaction_id == msg.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        throw std::runtime_error("Transaction already in progress");
    }
    auto trans =
        std::make_shared<transaction>(msg, ep, this->shared_from_this());
    trans->run(std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
               retries);
    this->_transactions.insert(state, *trans);
    utils::scope_guard on_exit([&]() noexcept {
        this->_transactions.erase(this->_transactions.iterator_to(*trans));
        trans->stop();
    });
    co_await trans->done();
    auto resp = std::move(trans->response);
    auto resp_from = trans->response_from;
    co_return std::make_tuple(std::move(resp), std::move(resp_from));
}

template <is_stream_layer NextLayer>
bool client<NextLayer>::dispatch(std::unique_ptr<stun::message> resp) noexcept {
    if (!resp)
        return false;
    utils::scope_guard on_exit(
        [&]() noexcept { this->message_pool().push_back(std::move(resp)); });
    auto it = this->_transactions.find(resp->transaction_id);
    if (it == this->_transactions.end())
        return false;
    auto &trans = it->second;
    if (!trans.response) {
        trans.response = std::move(resp);
        on_exit.dismiss();
    }
    trans.done_promise.set_value();
    return true;
}

template <is_stream_layer NextLayer>
ice::task<std::unique_ptr<stun::message>>
client<NextLayer>::request(const stun::message &msg, auto timeout) {
    auto it = this->_transactions.lower_bound(msg.transaction_id);
    if (it != this->_transactions.end() &&
        it->transaction_id == msg.transaction_id) {
        ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
        throw std::runtime_error("Transaction already in progress");
    }
    transaction trans{.transaction_id = msg.transaction_id};
    this->_transactions.insert(it, trans);
    utils::scope_guard on_exit([&]() noexcept { trans.unlink(); });

    boost::container::small_vector<std::byte, 1024> buf;
    buf.resize(msg.serialized_size());
    msg.write_to(buf.data(), buf.size());

    net::steady_timer timer(this->context());
    const auto begin = std::chrono::steady_clock::now();
    timer.expires_after(timeout);
    auto ret = co_await utils::stop_when(
        net::async_write(this->socket(), net::buffer(buf),
                         net::as_tuple(asio2exec::use_sender)),
        timer.async_wait(asio2exec::use_sender));
    if (!ret) {
        ICE_IN_DEBUG { std::cout << "Write timed out\n"; }
        co_return nullptr;
    }
    if (std::get<0>(*ret)) {
        ICE_IN_DEBUG {
            std::cout << "Write failed:" << std::get<0>(*ret).message() << "\n";
        }
        co_return nullptr;
    }
    if (!trans.response) {
        const auto now = std::chrono::steady_clock::now();
        if (now - begin >= timeout) {
            ICE_IN_DEBUG { std::cout << "Read timed out\n"; }
            co_return nullptr;
        }
        timer.expires_after(timeout - (now - begin));
        auto done =
            co_await utils::stop_when(trans.done_promise.get_future(),
                                      timer.async_wait(asio2exec::use_sender));
        if (!done) {
            ICE_IN_DEBUG { std::cout << "Read timed out\n"; }
            co_return nullptr;
        }
    }
    assert(trans.response);
    auto resp = std::move(trans.response);
    co_return resp;
}

} // namespace ice::stun