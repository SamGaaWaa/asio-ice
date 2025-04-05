#include "address.hpp"
#include "scope_guard.hpp"

#ifdef _WIN32
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <cstring>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/types.h>
#endif

namespace ice {

std::vector<net::ip::address> get_local_addresses() {
    std::vector<net::ip::address> addresses;

#ifdef _WIN32
    PIP_ADAPTER_ADDRESSES adapter_addrs = nullptr;
    ULONG out_buf_len = 0;
    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                                     nullptr, nullptr, &out_buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        adapter_addrs = static_cast<PIP_ADAPTER_ADDRESSES>(malloc(out_buf_len));
        if (!adapter_addrs) {
            return {};
        }
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                                   adapter_addrs, &out_buf_len);
    }
    if (ret != ERROR_SUCCESS) {
        free(adapter_addrs);
        return {};
    }

    utils::scope_guard on_exit([&]() noexcept { free(adapter_addrs); });

    addresses.reserve(16);
    for (PIP_ADAPTER_ADDRESSES adapter = adapter_addrs; adapter != nullptr;
         adapter = adapter->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress;
             addr != nullptr; addr = addr->Next) {
            auto sa = addr->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                auto sa_in = reinterpret_cast<struct sockaddr_in *>(sa);
                net::ip::address_v4::bytes_type bytes;
                std::memcpy(bytes.data(), &sa_in->sin_addr.s_addr, 4);
                addresses.emplace_back(net::ip::address_v4(bytes));
            } else if (sa->sa_family == AF_INET6) {
                auto sa_in6 = reinterpret_cast<struct sockaddr_in6 *>(sa);
                net::ip::address_v6::bytes_type bytes;
                std::memcpy(bytes.data(), sa_in6->sin6_addr.u.Byte, 16);
                addresses.emplace_back(
                    net::ip::address_v6(bytes, sa_in6->sin6_scope_id));
            }
        }
    }
#else
    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        return {};
    }

    utils::scope_guard on_exit([&]() noexcept { freeifaddrs(ifaddr); });

    addresses.reserve(16);
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        const int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            auto sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
            net::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &sa->sin_addr.s_addr, 4);
            addresses.emplace_back(net::ip::address_v4(bytes));
        } else if (family == AF_INET6) {
            auto sa6 = reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
            net::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), sa6->sin6_addr.s6_addr, 16);
            addresses.emplace_back(
                net::ip::address_v6(bytes, sa6->sin6_scope_id));
        }
    }
#endif

    return addresses;
}

std::string endpoint::to_string() const {
    return address.to_string() + ":" + std::to_string(port);
}

} // namespace ice