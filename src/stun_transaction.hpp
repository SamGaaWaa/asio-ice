#pragma once

#include "config.hpp"
#include "any_transport.hpp"
#include "stun.hpp"
#include "shared_promise.hpp"
#include "stop_when.hpp"
#include "task.hpp"
#include "scope_guard.hpp"
#include "receiver.hpp"
#include "inplace_receiver.hpp"

#include <boost/intrusive/set.hpp>
#include <boost/container/small_vector.hpp>

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
namespace asioice {
namespace net = boost::asio;
}
#else
#include "asio2exec.hpp"
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
namespace asioice {
namespace net = asio;
}
#endif

namespace asioice::stun {

struct transaction
    : boost::intrusive::set_base_hook<
          boost::intrusive::link_mode<boost::intrusive::auto_unlink>> {
    using base_type = boost::intrusive::set_base_hook<
        boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;

    enum state_t { INIT, DONE, ERR };

    struct comparer {
        using type = std::array<uint8_t, 12>;
        const type &operator()(const transaction &t) const noexcept {
            return t.request.transaction_id;
        }
    };

    transaction(net::io_context &ctx, const stun::message &req,
                const asioice::endpoint &stun_server, stun::message &resp) noexcept
        : _ctx{ctx}, request{req}, server{stun_server}, response{resp},
          _timer{ctx} {}

    transaction(const transaction &) = delete;
    transaction &operator=(const transaction &) = delete;
    transaction(transaction &&) = delete;
    transaction &operator=(transaction &&) = delete;

    template <class Transport> auto run(Transport &transport) {
        return utils::stop_when(
                   retry(transport),
                   _stop_retry.get_future() |
                       stdexec::continues_on(asio2exec::scheduler{_ctx})) |
               stdexec::then([](auto &&...) {});
    }

    state_t state() const noexcept { return _state; }

    void set_state(state_t s) noexcept {
        _state = s;
        _done.set_value(s);
    }

    std::size_t max_retries() const noexcept { return _max_retries; }

    void set_max_retries(std::size_t max_retries) noexcept {
        _max_retries = max_retries;
    }

    bool is_retring() const noexcept { return _retring; }

    void stop_retring() noexcept { _stop_retry.set_value(); }

    auto on_state_change() noexcept { return _done.get_future(); }

    const stun::message &request;
    asioice::endpoint server;
    stun::message &response;
    asioice::endpoint response_source;
    const void *response_transport{nullptr};

  private:
    template <class Transport>
    asioice::task<void> retry(Transport &transport) noexcept try {
        if (_retring) {
            ICE_IN_DEBUG { std::cerr << "Already retring\n"; }
            co_return;
        }
        _retring = true;
        utils::scope_guard on_exit([this]() noexcept { _retring = false; });

        boost::container::small_vector<std::byte, 1024> buf;
        std::chrono::milliseconds retry_rto{500};

        buf.resize(request.serialized_size());
        {
            auto n = request.write_to(buf.data(), buf.size());
            if (n < 0) {
                ICE_IN_DEBUG {
                    std::cerr << "USERNAME, NONCE or REALM too long\n";
                }
                set_state(state_t::ERR);
                co_return;
            }
            buf.resize(n);
        }

        for (std::size_t i = 0;; ++i) {
            auto [ec, _] = co_await transport.async_send_to(
                net::const_buffer(buf.data(), buf.size()), server);
            if (ec) {
                ICE_IN_DEBUG {
                    std::cerr << "STUN transaction failed: " << ec.message()
                              << '\n';
                }
                set_state(state_t::ERR);
                co_return;
            }
            _timer.expires_after(retry_rto);
            retry_rto *= 2;
            ec = co_await _timer.async_wait(asio2exec::use_sender);
            if (ec) {
                ICE_IN_DEBUG {
                    std::cerr << "STUN transaction failed: " << ec.message()
                              << '\n';
                }
                set_state(state_t::ERR);
                co_return;
            }
        }
        co_return;
    } catch (...) {
        set_state(state_t::ERR);
        throw;
    }

    net::io_context &_ctx;
    net::steady_timer _timer;
    std::size_t _max_retries{7};
    bool _retring{false};
    asioice::shared_promise<void> _stop_retry;
    asioice::shared_promise<state_t> _done;
    state_t _state{INIT};
};

using transaction_set = boost::intrusive::set<
    transaction, boost::intrusive::key_of_value<typename transaction::comparer>,
    boost::intrusive::constant_time_size<false>>;

inline bool dispatch_stun_response(transaction_set &transactions,
                                   const asioice::endpoint &source,
                                   const void *data, std::size_t size,
                                   const void *transport) noexcept {
    if (message::is_not_stun(data, size) || !message::is_response(data, size))
        return false;
    std::array<uint8_t, 12> transaction_id{};
    std::copy_n(message::get_transaction_id(data, size), 12,
                transaction_id.data());

    auto it = transactions.find(transaction_id);
    if (it == transactions.end()) {
        ICE_IN_DEBUG { std::cout << "Unknown transaction id\n"; }
        // TODO: May be an application message
        return false;
    }
    it->response_transport = transport;
    it->response.reset();
    if (!it->response.parse(data, size)) {
        ICE_IN_DEBUG { std::cerr << "Parse response failed\n"; }
        return false;
    }
    it->response_source = source;
    it->set_state(transaction::state_t::DONE);
    return true;
}

struct basic_request_t {
    template <class Transport>
    asioice::task<bool>
    operator()(Transport &transport, transaction_set &transactions,
               const stun::message &req, const asioice::endpoint &server,
               stun::message &resp, asioice::endpoint &from, std::size_t retries,
               auto... self) const noexcept {
        auto it = transactions.lower_bound(req.transaction_id);
        if (it != transactions.end() &&
            it->request.transaction_id == req.transaction_id) {
            ICE_IN_DEBUG { std::cout << "Transaction already in progress\n"; }
            co_return false;
        }
        stun::transaction trans(transport.context(), req, server, resp);
        transactions.insert(it, trans);

        response_receiver<Transport> receiver{transport, transactions};
        transport.add_receiver(receiver);

        bool ret = false;
        utils::inplace_receiver<void> retry_receiver;
        auto retry_op = retry_receiver.start(stdexec::starts_on(
            asio2exec::scheduler{transport.context()}, trans.run(transport)));
        stdexec::start(retry_op);

        ret = false;
        auto new_state =
            co_await (trans.on_state_change() | stdexec::stopped_as_optional());
        if (!new_state.has_value()) {
            goto END;
        }
        if (trans.state() == stun::transaction::state_t::ERR) {
            goto END;
        }
        assert(trans.state() == stun::transaction::state_t::DONE);
        assert(resp.transaction_id == req.transaction_id);
        assert(resp.is_response());
        if (resp.cls == stun::class_t::STUN_CLASS_RESP_ERROR &&
            !resp.error_code.has_value()) {
            goto END;
        }
        ret = true;
    END:
        from = trans.response_source;
        receiver.unlink();
        trans.unlink();
        trans.stop_retring();
        co_await retry_receiver.wait();
        co_return ret;
    }

  private:
    template <class Transport1>
    struct response_receiver : asioice::datagram_receiver {
        explicit response_receiver(Transport1 &t,
                                   transaction_set &transactions) noexcept
            : asioice::datagram_receiver(), _transport(t),
              _transactions(transactions) {}

        bool datagram_received(io_buffer_ptr &buffer,
                               const asioice::endpoint &endpoint) override {
            if constexpr (std::is_same_v<std::decay_t<Transport1>,
                                         asioice::any_transport>) {
                return dispatch_stun_response(_transactions, endpoint,
                                              buffer->data(), buffer->size(),
                                              _transport.data());
            } else {
                return dispatch_stun_response(_transactions, endpoint,
                                              buffer->data(), buffer->size(),
                                              &_transport);
            }
        }

      private:
        Transport1 &_transport;
        transaction_set &_transactions;
    };
};

inline constexpr basic_request_t basic_request{};

} // namespace asioice::stun