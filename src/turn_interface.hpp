#pragma once

#include "config.hpp"
#include "address.hpp"
#include "task.hpp"

#include <chrono>
#include <string>
#include <optional>
#include <span>

namespace asioice::turn {

struct turn_interface {
    virtual asioice::endpoint local_endpoint() const noexcept = 0;
    virtual asioice::endpoint remote_endpoint() const noexcept = 0;
    virtual const std::string &username() const noexcept = 0;
    virtual const std::string &password() const noexcept = 0;
    virtual std::optional<asioice::endpoint>
    relayed_address() const noexcept = 0;
    virtual std::optional<asioice::endpoint>
    reflex_address() const noexcept = 0;
    virtual asioice::task<std::optional<asioice::endpoint>>
    create_allocation(std::chrono::seconds lifetime) = 0;
    virtual asioice::task<bool> channel_bind(net::ip::udp::endpoint peer) = 0;
    virtual asioice::task<void> delete_allocation() = 0;
    virtual asioice::task<bool>
    refresh(std::chrono::seconds time_to_expiry) = 0;
    virtual bool has_permission(const net::ip::address ip) const noexcept = 0;
    virtual asioice::task<bool> create_permission(net::ip::address peer) = 0;
    virtual asioice::task<bool>
    create_permission(std::span<net::ip::address> peers) = 0;
    virtual void delete_permission(const net::ip::address &peer) noexcept = 0;
    virtual void
    delete_permission(std::span<net::ip::address> peers) noexcept = 0;
};

} // namespace asioice::turn