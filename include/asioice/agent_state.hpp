#pragma once

namespace asioice {

enum struct agent_state_t : char {
    INIT,
    GATHERING,
    CONNECTING,
    CONNECTED,
    CLOSED
};

} // namespace asioice