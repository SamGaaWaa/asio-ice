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
    static constexpr std::size_t frame_size(std::size_t data_size) noexcept {
        return data_size + sizeof(uint16_t);
    }

  public:
    static constexpr std::size_t max_packet_size = 4096;

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
        return true;
    }

    bool empty() const noexcept { return _q.empty(); }

    std::span<const uint8_t> peek() const noexcept {
        assert(!empty());
        const auto &item = _q.front();
        uint16_t n = 0;
        std::memcpy(&n, item.data.data() + item.begin_offset, sizeof(uint16_t));
        return {item.data.data() + item.begin_offset + sizeof(uint16_t), n};
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
    }

    void clear() noexcept {
        _q.clear();
        _bytes = 0;
    }

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

    struct item {
        item() noexcept = default;

        std::array<uint8_t, max_packet_size> data;
        std::size_t begin_offset{0};
        std::size_t end_offset{0};
    };

    std::list<item> _q{};
    std::size_t _bytes{0};
    const std::size_t _max_bytes{0};
};

} // namespace asioice::utils