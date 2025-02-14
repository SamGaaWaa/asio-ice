#pragma once

#define ASIOICE_USE_BOOST 0

#ifdef NDEBUG
    #define ICE_DEBUG 0
#else
    #define ICE_DEBUG 1
#endif

#define ICE_IN_DEBUG if constexpr(! ICE_DEBUG){} else

