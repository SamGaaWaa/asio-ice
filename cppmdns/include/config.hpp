#pragma once

#define CPPMDNS_USE_BOOST_ASIO 1

#ifdef NDEBUG
    #define CPPMDNS_DEBUG 0
#else
    #define CPPMDNS_DEBUG 1
#endif

#define CPPMDNS_IN_DEBUG if constexpr(! CPPMDNS_DEBUG){} else

