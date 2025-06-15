#pragma once

#include "address.hpp"
#include "message.hpp"
#include "shared_promise_v2.hpp"

#include <deque>
#include <functional>
#include <stdexcept>

namespace ice {

struct message_pool {
    using value_type = std::pair<ice::message, ice::endpoint>;
    using queue_type = std::deque<value_type>;

    message_pool(fixed_buffer_pool &buffer_pool, std::size_t max = 128) noexcept
        : _buffer_pool(buffer_pool), _max(max) {}
    message_pool(const message_pool &) = delete;
    message_pool &operator=(const message_pool &) = delete;
    message_pool(message_pool &&) = delete;
    message_pool &operator=(message_pool &&) = delete;

    auto &buffer_pool() noexcept { return _buffer_pool; }
    const auto &buffer_pool() const noexcept { return _buffer_pool; }

    std::size_t size(message_type type) const noexcept {
        return get_pool(type).size();
    }

    std::size_t max_size() const noexcept { return _max; }

    queue_type &get_pool(message_type type) {
        switch (type) {
        case message_type::stun:
            return _stun;
        case message_type::zrtp:
            return _zrtp;
        case message_type::dtls:
            return _dtls;
        case message_type::srtp:
            return _srtp;
        case message_type::turn_channel:
            return _turn_channel;
        case message_type::rtp_rtcp:
            return _rtp_rtcp;
        case message_type::unknown:
            return _other;
        }
        throw std::runtime_error("Unknown message type");
    }

    const queue_type &get_pool(message_type type) const {
        switch (type) {
        case message_type::stun:
            return _stun;
        case message_type::zrtp:
            return _zrtp;
        case message_type::dtls:
            return _dtls;
        case message_type::srtp:
            return _srtp;
        case message_type::turn_channel:
            return _turn_channel;
        case message_type::rtp_rtcp:
            return _rtp_rtcp;
        case message_type::unknown:
            return _other;
        }
        throw std::runtime_error("Unknown message type");
    }

    auto wait(message_type type) noexcept {
        return get_promise(type).get_future();
    }

    void notify(message_type type) noexcept { get_promise(type).set_value(); }

  private:
    ice::shared_promise<void> &get_promise(message_type type) {
        switch (type) {
        case message_type::stun:
            return _notify_stun;
        case message_type::zrtp:
            return _notify_zrtp;
        case message_type::dtls:
            return _notify_dtls;
        case message_type::srtp:
            return _notify_srtp;
        case message_type::turn_channel:
            return _notify_turn_channel;
        case message_type::rtp_rtcp:
            return _notify_rtp_rtcp;
        case message_type::unknown:
            return _notify_other;
        }
        throw std::runtime_error("Unknown message type");
    }

    fixed_buffer_pool &_buffer_pool;
    std::size_t _max;
    queue_type _stun, _zrtp, _dtls, _srtp, _turn_channel, _rtp_rtcp, _other;
    ice::shared_promise<void> _notify_stun, _notify_zrtp, _notify_dtls,
        _notify_srtp, _notify_turn_channel, _notify_rtp_rtcp, _notify_other;
};

} // namespace ice