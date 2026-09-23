#pragma once

#include <cassert>
#include <cstdint>
#include <list>
#include <array>
#include <span>
#include <cstring>
#include <numeric>
#include <limits>
#include <stdexcept>

namespace asioice::utils {

struct packet_queue {
  private:
    static constexpr std::size_t max_packet_size = 1200 * 10;
    static_assert(max_packet_size <= std::numeric_limits<std::uint16_t>::max());

    static constexpr std::size_t frame_size(std::size_t data_size) noexcept {
        return data_size + sizeof(uint16_t);
    }

    struct item {
        item() noexcept = default;

        std::array<uint8_t, max_packet_size> data;
        std::size_t begin_offset{0};
        std::size_t end_offset{0};
    };

  public:
    packet_queue(std::size_t max_payload_bytes = 16 * 1024)
        : _max_bytes{max_payload_bytes} {
        if (max_payload_bytes < max_packet_size)
            throw std::runtime_error{"max_payload_bytes < max_packet_size"};
    }

    bool write(std::span<const uint8_t> data) {
        if (data.empty())
            return true;
        auto fs = frame_size(data.size());
        if (_bytes + fs > _max_bytes) [[unlikely]]
            return false;
        if (fs > max_packet_size) [[unlikely]]
            return false;
        if (_q.empty() || _q.back().end_offset + fs > max_packet_size)
            _q.emplace_back();
        write_frame(data);
        ++_count;
        return true;
    }

    bool empty() const noexcept { return _q.empty(); }
    std::size_t count() const noexcept { return _count; }

    std::span<const uint8_t> peek() const noexcept {
        assert(!empty());
        const auto &item = _q.front();
        uint16_t n = 0;
        std::memcpy(&n, item.data.data() + item.begin_offset, sizeof(uint16_t));
        return {item.data.data() + item.begin_offset + sizeof(uint16_t), n};
    }

    struct auto_pop {
        std::size_t count() const noexcept { return _count; }

        auto_pop(const auto_pop &) = delete;
        auto_pop &operator=(const auto_pop &) = delete;
        auto_pop(auto_pop &&) = delete;
        auto_pop &operator=(auto_pop &&) = delete;

        void disable() noexcept { _auto = false; }

        ~auto_pop() {
            if (!_auto)
                return;
            _self._q.erase(_self._q.begin(), _last);
            if (_last_offset == _last->end_offset)
                _self._q.pop_front();
            else
                _last->begin_offset = _last_offset;
            _self._bytes -= _bytes;
            _self._count -= _count;
        }

      private:
        friend struct packet_queue;
        auto_pop(packet_queue &q, std::size_t n, std::list<item>::iterator last,
                 std::size_t last_offset, std::size_t bytes) noexcept
            : _self{q}, _auto{true}, _count{n}, _last{last},
              _last_offset{last_offset}, _bytes{bytes} {}

        auto_pop(packet_queue &q) noexcept : _self{q}, _auto{false} {}

        packet_queue &_self;
        bool _auto;
        std::size_t _count;
        std::list<item>::iterator _last;
        std::size_t _last_offset;
        std::size_t _bytes;
    };

    auto_pop peek(std::span<const uint8_t> *pkt, std::size_t max_count) {
        if (empty())
            return auto_pop{*this};
        std::size_t total = 0;
        std::size_t total_bytes = 0;
        auto it = _q.begin();
        std::size_t offset = it->begin_offset;
        auto last = it;
        std::size_t last_offset = offset;
        while (total < max_count && it != _q.end()) {
            uint16_t n = 0;
            std::memcpy(&n, it->data.data() + offset, sizeof(uint16_t));
            pkt[total] = std::span<const uint8_t>{
                it->data.data() + offset + sizeof(uint16_t), n};
            ++total;
            total_bytes += frame_size(n);
            offset += frame_size(n);
            last = it;
            last_offset = offset;
            if (offset == it->end_offset) {
                ++it;
                if (it != _q.end())
                    offset = it->begin_offset;
            }
        }
        return auto_pop{*this, total, last, last_offset, total_bytes};
    }

    void pop() noexcept {
        assert(!empty());
        auto &item = _q.front();
        uint16_t n = 0;
        std::memcpy(&n, item.data.data() + item.begin_offset, sizeof(uint16_t));
        item.begin_offset += frame_size(n);
        if (item.begin_offset == item.end_offset) [[unlikely]]
            _q.pop_front();
        _bytes -= frame_size(n);
        --_count;
    }

    void clear() noexcept {
        _q.clear();
        _bytes = 0;
    }

    std::size_t buffered_bytes() const noexcept { return _bytes; }

    std::size_t max_buffered_bytes() const noexcept { return _max_bytes; }

  private:
    void write_frame(std::span<const uint8_t> data) noexcept {
        assert(data.size() <= std::numeric_limits<uint16_t>::max());
        uint16_t h = (uint16_t)data.size();
        auto &item = _q.back();
        std::memcpy(item.data.data() + item.end_offset, &h, sizeof(uint16_t));
        item.end_offset += sizeof(uint16_t);
        std::memcpy(item.data.data() + item.end_offset, data.data(),
                    data.size());
        item.end_offset += data.size();
        _bytes += frame_size(data.size());
    }

    std::list<item> _q{};
    std::size_t _count{0};
    std::size_t _bytes{0};
    const std::size_t _max_bytes{0};
};

} // namespace asioice::utils