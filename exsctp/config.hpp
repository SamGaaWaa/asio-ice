#pragma once

#ifdef NDEBUG
#define SCTP_DEBUG 0
#else
#define SCTP_DEBUG 1
#endif

#define SCTP_IN_DEBUG                                                           \
    if constexpr (!SCTP_DEBUG) {                                                \
    } else
