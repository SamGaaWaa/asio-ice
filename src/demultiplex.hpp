#pragma once

#include "config.hpp"
#include "message.hpp"
#include "scope_guard.hpp"
#include "shared_promise_v2.hpp"
#include "task.hpp"

#if ASIOICE_USE_BOOST_ASIO > 0
#define ASIO_TO_EXEC_USE_BOOST 1
#include <boost/asio/buffer.hpp>
namespace ice {
namespace net = boost::asio;
}
#else
#include <asio/buffer.hpp>
namespace ice {
namespace net = asio;
}
#endif

#include "asio2exec.hpp"
#include "exec/repeat_effect_until.hpp"

#include <algorithm>
#include <cstdint>
#include <ranges>
#include <vector>

namespace ice {

template <class NextLayer, bool IsDatagram = true> struct demultiplexer {
    using next_layer_type = NextLayer;
    using endpoint_type = typename next_layer_type::endpoint_type;

    demultiplexer(NextLayer &next_layer, std::size_t mtu,
                  std::size_t max_cache = 128) noexcept
        : _sock(next_layer), _mtu(mtu), _max_cache(max_cache) {}

    demultiplexer(const demultiplexer &) = delete;
    demultiplexer &operator=(const demultiplexer &) = delete;
    demultiplexer(demultiplexer &&) = delete;
    demultiplexer &operator=(demultiplexer &&) = delete;

    auto local_endpoint() const { return _sock.local_endpoint(); }

    ice::task<std::error_code> async_read(message_type need_type,
                                          std::vector<std::byte> &msg,
                                          endpoint_type &from)
        requires(IsDatagram)
    {
        if (need_type == message_type::unknown)
            co_return std::make_error_code(std::errc::invalid_argument);
        while (true) {
            auto it =
                std::ranges::find_if(_cache, [&, this](const auto &a) noexcept {
                    return a.type == need_type;
                });
            if (it != _cache.end()) {
                put_buffer(msg);
                from = std::move(it->from);
                msg = std::move(it->data);
                _cache.erase(it);
                _notify_cache_changed.set_value();
                co_return std::error_code{};
            }
            std::vector<std::byte> buf = get_buffer();
            utils::scope_guard put_back([&]() noexcept { put_buffer(buf); });
            auto [ec, n] = co_await _sock.async_receive_from(
                net::buffer(buf.data(), buf.size()), from,
                asio2exec::use_sender);
            if (ec)
                co_return ec;
            if (n == 0)
                co_return std::make_error_code(std::errc::connection_aborted);
            message_type type = get_message_type(buf.data());
            if (need_type == type) {
                buf.resize(n);
                put_buffer(msg);
                msg = std::move(buf);
                put_back.dismiss();
                co_return std::error_code{};
            }
            while (_cache.size() >= _max_cache)
                co_await _notify_cache_changed.get_future();
            buf.resize(n);
            _cache.emplace_back(type, std::move(buf), from);
            put_back.dismiss();
            _notify_cache_changed.set_value();
            continue;
        }
    }

    template <class ConstBufferSequence, class... Args>
    auto async_send_to(const ConstBufferSequence &buffers,
                       const endpoint_type &to, Args &&...args) {
        return _sock.async_send_to(buffers, to, std::forward<Args>(args)...);
    }

    ice::task<void> push_cache(message_type type, std::vector<std::byte> data,
                               const endpoint_type &from)
        requires(IsDatagram)
    {
        while (_cache.size() >= _max_cache)
            co_await _notify_cache_changed.get_future();
        _cache.emplace_back(type, std::move(data), from);
    }

  private:
    struct message {
        message_type type;
        std::vector<std::byte> data;
        endpoint_type from;
    };

    void put_buffer(std::vector<std::byte> &buffer) {
        if (buffer.size() < _mtu)
            return;
        _free_list.push_back(std::move(buffer));
    }

    std::vector<std::byte> get_buffer() {
        if (_free_list.empty())
            return std::vector<std::byte>(_mtu);
        auto b = std::move(_free_list.front());
        _free_list.pop_front();
        return b;
    }

    NextLayer &_sock;
    std::size_t _mtu;
    std::size_t _max_cache;
    std::deque<std::vector<std::byte>> _free_list{};
    std::deque<message> _cache{};
    ice::shared_promise<void> _notify_cache_changed{};
};

template <class NextLayer>
using datagram_demultiplexer = demultiplexer<NextLayer, true>;

} // namespace ice