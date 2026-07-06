#pragma once

#include <vector>
#include <cstdint>
#include <optional>
#include <string>

namespace asioice::impl {

struct data_channel_message {
    std::vector<uint8_t> data;
    bool binary;
};

enum struct data_channel_priority : uint16_t {
    very_low = 128,
    low = 256,
    medium = 512,
    high = 1024
};

struct data_channel_options {
    bool ordered = true;
    std::optional<uint32_t> max_packet_life_time{};
    std::optional<uint32_t> max_retransmits{};
    std::string protocol = "";
    bool negotiated = false;
    uint16_t stream_id = 0;
    data_channel_priority priority = data_channel_priority::low;
};

} // namespace asioice::impl