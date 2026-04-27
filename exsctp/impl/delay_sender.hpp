#pragma once

#include <cstdint>
#include <memory>
#include <chrono>

#include "task.hpp"
#include "utils/scope_guard.hpp"

namespace exsctp::impl {

template <class IOInterface>
struct delay_sende_impl: std::enable_shared_from_this<delay_sende_impl<IOInterface>> {

private:
    auto send() noexcept {
        std::vector<uint8_t> data;
        std::swap(data, this->_buf);
        return stdexec::just(std::move(data)) |
                stdexec::let_value([this](std::vector<uint8_t>& data) {
                    return this->_interface->send(std::span<const uint8_t>{data});
                }) |
                stdexec::then([this](auto&& result) {
                    this->_last_send_time = std::chrono::steady_clock::now();
                    return std::move(result);
                });
    }

    exsctp::inline_task<void> send_loop(const std::vector<uint8_t>& data) {
        SCTP_IN_DEBUG{ std::cout << "delay_sender: send_loop started\n"; };
        this->_sending = true;
        utils::scope_guard on_exit([this]() noexcept {
            this->_sending = false;
            SCTP_IN_DEBUG{ std::cout << "delay_sender: send_loop exited\n"; };
        });
        std::vector<uint8_t> buf;
        while (true) {
            auto now = std::chrono::steady_clock::now();
            if (this->_buf.empty()) {
                if (this->_last_send_time + this->_delay <= now)
                    co_return;
                co_await this->_interface->scheduler_at(this->_last_send_time + this->_delay);
                continue;
            }
            if (this->_serialize_time + this->_delay > now) {
                co_await this->_interface->scheduler_after(this->_serialize_time + this->_delay - now);
            }
            if (this->_buf.empty())
                continue;
            buf.clear();
            std::swap(buf, this->_buf);
            co_await this->_interface->send(std::span<const uint8_t>(buf));
            this->_last_send_time = std::chrono::steady_clock::now();
        }
    }

    std::shared_ptr<IOInterface> _interface;
    std::chrono::milliseconds _delay;
    std::size_t _mtu;
    std::vector<uint8_t> _buf{};
    std::chrono::steady_clock::time_point _last_send_time{};
    std::chrono::steady_clock::time_point _serialize_time{};
    bool _sending{false};
};

template <class IOInterface>
struct delay_sender {

private:
    std::shared_ptr<delay_sende_impl<IOInterface>> _impl;
};

} // namespace exsctp::impl