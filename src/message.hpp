#pragma once

#include "binary.hpp"
#include "config.hpp"
#include "fixed_buffer.hpp"
#include "stun.hpp"

#include <cstdint>
#include <vector>

namespace ice {

enum struct message_type : uint8_t {
    stun,
    zrtp,
    dtls,
    srtp,
    turn_channel,
    rtp_rtcp,
    unknown
};

constexpr message_type get_message_type(uint8_t b) noexcept {
    if (b <= 3)
        return message_type::stun;
    if (b >= 16 && b <= 19)
        return message_type::zrtp;
    if (b >= 20 && b <= 63)
        return message_type::dtls;
    if (b >= 64 && b <= 79)
        return message_type::turn_channel;
    if (b >= 128 && b <= 191)
        return message_type::rtp_rtcp;
    return message_type::unknown;
}

constexpr message_type get_message_type(const void *data) noexcept {
    return get_message_type(*static_cast<const uint8_t *>(data));
}

inline bool validate_message(message_type type, const void *data,
                             std::size_t size) noexcept {
    if (size == 0)
        return false;
    if (type != get_message_type(data))
        return false;
    switch (type) {
    case message_type::stun:
        if (stun::message::is_not_stun(data, size))
            return false;
        return true;
    case message_type::zrtp:
        return true;
    case message_type::dtls:
        return true;
    case message_type::turn_channel: {
        if (size < 4)
            return false;
        uint16_t channel_number = binary::read_big<uint16_t>(data);
        uint16_t len = binary::read_big<uint16_t>((const char *)data + 2);
        if (channel_number < 0x4000 || channel_number > 0x4FFF)
            return false;
        if (size == len + 4)
            return true;
        if (len & 3) {
            auto pad = 4 - (len & 3);
            return size == len + 4 + pad;
        }
        return false;
    }
    case message_type::rtp_rtcp:
        return true;
    default:
        return true;
    }
}

struct message {
    message(fixed_buffer data, message_type type) noexcept
        : _data(std::move(data)), _buffer(_data.mutable_buffer()), _type(type) {
        assert(!_data.empty());
    }

    message(const message &other) = delete;
    message &operator=(const message &other) = delete;

    message(message &&other) noexcept
        : _data(std::move(other._data)), _buffer(std::move(other._buffer)),
          _type(other._type) {}

    message &operator=(message &&other) noexcept {
        if (this != &other) {
            _data = std::move(other._data);
            _buffer = std::move(other._buffer);
            _type = other._type;
        }
        return *this;
    }

    const fixed_buffer &origin_buffer() const noexcept { return _data; }
    const auto &buffer() const noexcept { return _buffer; }
    const void *data() const noexcept { return _buffer.data(); }
    std::size_t size() const noexcept { return _buffer.size(); }
    message_type type() const noexcept { return _type; }
    message_type &type() noexcept { return _type; }

    message &operator+=(std::size_t n) noexcept {
        _buffer += n;
        return *this;
    }

    message &operator=(const net::const_buffer &b) noexcept {
        assert((const char *)b.data() >= (const char *)data() &&
               (const char *)b.data() + b.size() <=
                   (const char *)data() + size());
        _buffer = b;
        return *this;
    }

  private:
    fixed_buffer _data;
    net::const_buffer _buffer{};
    message_type _type{message_type::unknown};
};

} // namespace ice