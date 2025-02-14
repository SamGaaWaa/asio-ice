#pragma once

#include "config.hpp"
#include "inline_task.hpp"
#include "stun.hpp"
#include "shared_promise_v2.hpp"
#include "async_queue.hpp"

#include <boost/circular_buffer.hpp>
#include <boost/intrusive/set.hpp>

#if ASIOICE_USE_BOOST > 0
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
namespace ice {
	namespace net = boost::asio;
}
#else
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
namespace ice {
	namespace net = asio;
}
#endif

#include "exec/task.hpp"

#include <memory>
#include <chrono>

namespace ice::stun {

class client: public std::enable_shared_from_this<client> {
public:
    client(net::io_context& ctx, net::ip::udp::socket& sock)noexcept:
        _ctx(ctx),
        _sock(sock),
        _msg_pool(16)
    {}

    client(const client&) = delete;
    client& operator=(const client&) = delete;
    client(client&&) = delete;
    client& operator=(client&&) = delete;

    void stop()noexcept;
    bool is_running()const noexcept { return _running; }

    bool dispatch(const net::ip::udp::endpoint& ep, const void *data, std::size_t size);

    inline_task<std::tuple<std::unique_ptr<stun::message>, net::ip::udp::endpoint>>
    request(net::ip::udp::endpoint ep,
            std::unique_ptr<stun::message> msg,
            std::chrono::milliseconds timeout,
            std::size_t retries,
            std::shared_ptr<client> self = {});

    const auto& context()const noexcept { return _ctx; }
    auto& context()noexcept { return _ctx; }
    const auto& socket()const noexcept { return _sock; }
    auto& socket()noexcept { return _sock; }
    auto& message_pool()noexcept { return _msg_pool; }
    const auto& message_pool()const noexcept { return _msg_pool; }
private:
    struct transaction_t:
        std::enable_shared_from_this<transaction_t>,
        boost::intrusive::set_base_hook<
            boost::intrusive::link_mode<boost::intrusive::safe_link>
        >
    {
        transaction_t(
            const stun::message& msg,
            const net::ip::udp::endpoint& ep,
            std::shared_ptr<client> c
        ):
            transaction_id(msg.transaction_id),
            endpoint(ep),
            _client(std::move(c))
        {
            int ret = msg.write_to(_buf, sizeof(_buf));
            if (ret < 0) {
                throw std::runtime_error("stun::message::write_to() failed");
            }
            _buf_size = static_cast<std::size_t>(ret);
        }

        void run(std::chrono::milliseconds timeout, std::size_t max_retries);

        void stop()noexcept {
            _stop_promise.set_stopped();
        }

        void set_done()noexcept {
            _done_promise.set_value();
        }

        auto done()noexcept { return _done_promise.get_future(); }

        struct comparer {
            using type = std::array<uint8_t, 12>;
            const type& operator()(const transaction_t& t) const noexcept {
                return t.transaction_id;
            }
        };

        std::array<uint8_t, 12> transaction_id;
        net::ip::udp::endpoint endpoint;
        std::unique_ptr<stun::message> response{};
        net::ip::udp::endpoint response_from{};
    private:
        inline_task<void> retry(std::chrono::milliseconds timeout, std::size_t max_retries, std::shared_ptr<transaction_t> self);

        char _buf[2048];
        std::size_t _buf_size;
        std::shared_ptr<client> _client;
        shared_promise<void> _done_promise{};
        shared_promise<void> _stop_promise{};
    };

    using transaction_set = boost::intrusive::set<transaction_t, boost::intrusive::key_of_value<transaction_t::comparer>>;

    net::io_context& _ctx;
    net::ip::udp::socket& _sock;
    transaction_set _transactions{};
    boost::circular_buffer<std::unique_ptr<stun::message>> _msg_pool;
    bool _running = true;
    shared_promise<void> _stop_promise{};
};

} // namespace ice::stun