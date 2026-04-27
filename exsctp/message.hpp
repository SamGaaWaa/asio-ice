#pragma once

#include <cstdint>
#include <span>

namespace exsctp {

struct message {
    uint16_t stream_id;
    uint32_t ppid;
    std::span<uint8_t> data;
};

} // namespace exsctp
