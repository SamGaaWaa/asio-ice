#pragma once

#ifdef _MSC_VER
#if defined(_M_IX86) || defined(_M_X64)
#define __MDNS_LITTLE_ENDIAN__
#else
#define __MDNS_LITTLE_ENDIAN__ 
#endif
#else
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __MDNS_LITTLE_ENDIAN__
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __MDNS_BIG_ENDIAN__
#else
#define __MDNS_LITTLE_ENDIAN__
#endif
#endif