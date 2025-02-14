#include "stun_client.hpp"
#include "scope_guard.hpp"

#if ASIOICE_USE_BOOST > 0
#define ASIO_TO_EXEC_USE_BOOST
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/buffer.hpp>
#else
#include <asio/steady_timer.hpp>
#include <asio/buffer.hpp>
#endif

#include "asio2exec.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>

namespace ice::stun {

void client::stop()noexcept {
    if (!_running) return;
    _running = false;
    _stop_promise.set_stopped();
}

static std::unique_ptr<stun::message> get_message(auto& pool) {
    if (pool.empty())
        return std::make_unique<stun::message>();
    auto msg = std::move(pool.front());
    pool.pop_front();
    assert(msg != nullptr);
    msg->reset();
    return msg;
}

bool client::dispatch(
    const net::ip::udp::endpoint& ep,
    const void *data,
    std::size_t size)
{
    assert(_running);
    if (stun::message::is_not_stun(data, size))
        return false;
    auto msg = get_message(_msg_pool);
    if (!msg->parse(data, size) || !msg->is_response())
        return false;
    // TODO: handle message
    ICE_IN_DEBUG{
        // std::cout << "STUN message from " << ep.address()
        //           << ":" << ep.port()
        //           << ":\n" << msg->to_string() << "\n";
    }
    auto it = _transactions.find(msg->transaction_id);
    if (it == _transactions.end()) {
        ICE_IN_DEBUG{
            // std::cout << "Unknown transaction id\n";
        }
        // TODO: May be a application message
        return false;
    }
    it->response = std::move(msg);
    it->response_from = ep;
    it->set_done();
    return true;
}

// exec::task<void>
inline_task<void>
client::transaction_t::retry(
    std::chrono::milliseconds timeout,
    std::size_t max_retries, 
    std::shared_ptr<transaction_t> self)
{
    utils::scope_guard on_exit([this]()noexcept {
        _done_promise.set_value();
    });
    net::steady_timer timer{_client->context()};
    for (std::size_t i = 0; i < max_retries; ++i) {
        auto [err, n] = co_await _client->socket().async_send_to(net::buffer(_buf, _buf_size), this->endpoint, asio2exec::use_sender);
        if (err) {
            ICE_IN_DEBUG{
                // std::cerr << "STUN transaction failed: " << err.message() << "\n";
            }
            co_return;
        }
        if (n != _buf_size) {
            ICE_IN_DEBUG{
                // std::cerr << "STUN transaction failed: sent " << n << " bytes, expected " << _buf_size << "\n";
            }
            co_return;
        }
        timer.expires_after(timeout);
        timeout *= 2;
        err = co_await timer.async_wait(asio2exec::use_sender);
        if (err) {
            ICE_IN_DEBUG{
                // std::cerr << "STUN transaction failed: " << err.message() << "\n";
            }
            co_return;
        }
    }
    co_return;
}

void client::transaction_t::run(
    std::chrono::milliseconds timeout, 
    std::size_t max_retries)
{
    asio2exec::scheduler_t sched{_client->context()};
    stdexec::start_detached(stdexec::starts_on(
        sched,
        stdexec::when_all(
            retry(timeout, max_retries, shared_from_this()),
            _stop_promise.get_future() | stdexec::continues_on(sched)
        )
    ));
}

inline_task<std::tuple<std::unique_ptr<stun::message>, net::ip::udp::endpoint>>
client::request(
        net::ip::udp::endpoint ep,
        std::unique_ptr<stun::message> msg,
        std::chrono::milliseconds timeout,
        std::size_t retries,
        std::shared_ptr<client> self)
{
    assert(_running);
    auto state = _transactions.lower_bound(msg->transaction_id);
    if (state != _transactions.end() && state->transaction_id == msg->transaction_id) {
        ICE_IN_DEBUG{
            // std::cout << "Transaction already in progress\n";
        }
        throw std::runtime_error("Transaction already in progress");
    }
    auto trans = std::make_shared<transaction_t>(*msg, ep, shared_from_this());
    trans->run(timeout, retries);
    _transactions.insert(state, *trans);
    utils::scope_guard on_exit([&]()noexcept{
        this->_transactions.erase(this->_transactions.iterator_to(*trans));
        trans->stop();
    });
    co_await trans->done();
    auto resp = std::move(trans->response);
    auto resp_from = trans->response_from;
    co_return std::make_tuple(std::move(resp), std::move(resp_from));
}

} // namespace ice::stun