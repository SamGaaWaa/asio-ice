#pragma once

#include "config.hpp"
#include "io_buffer.hpp"
#include "address.hpp"
#include "receiver.hpp"

#include <vector>
#include <ranges>
#include <algorithm>

namespace ice::impl {

struct early_data_cache {
    early_data_cache(std::size_t max_bytes = 16 * 1024) noexcept:
        _max_bytes{max_bytes}
    {}

    early_data_cache(const early_data_cache&) = delete;
    early_data_cache(early_data_cache&&) = delete;
    early_data_cache& operator=(const early_data_cache&) = delete;
    early_data_cache& operator=(early_data_cache&&) = delete;

    bool put(ice::io_buffer_ptr& data, const ice::endpoint& source) {
        if (!data)
            return false;
        if (data->size() + _bytes > _max_bytes)
            return false;
        _early_data.emplace_back(std::move(data), source);
        _bytes += _early_data.back().data->size();
        return true;
    }

    void dispatch_receiver(ice::datagram_receiver& receiver) {
        if (this->_early_data.empty())
            return;
        std::vector<early_data_t> early_data{};
        receiver_list_t tmp{};

        early_data.swap(this->_early_data);
        this->_bytes = 0;
        tmp.push_back(receiver);
        utils::scope_guard on_exit([&]() noexcept {
            if (receiver.is_linked())
                receiver.unlink();
            if (this->_early_data.empty()) {
                std::swap(early_data, this->_early_data);
                for (const auto& data: this->_early_data)
                    this->_bytes += data.data->size();
            } else {
                for (auto& data: early_data) {
                    put(data.data, data.source);
                }
            }
        });
        for (auto& data: early_data) {
            ice::dispatch_receivers(tmp, data.data, data.source);
        }
        std::erase_if(early_data, [](const auto& data) noexcept {
            return !data.data;
        });
    }

    void clear() noexcept {
        std::vector<early_data_t>{}.swap(this->_early_data);
        this->_bytes = 0;
    }
private:
    using receiver_list_t =
        boost::intrusive::list<datagram_receiver,
                               boost::intrusive::constant_time_size<false>>;

    struct early_data_t {
      ice::io_buffer_ptr data;
      ice::endpoint source;
    };

    std::vector<early_data_t> _early_data{};
    std::size_t _bytes{0};
    const std::size_t _max_bytes;
};

} // namespace ice::impl