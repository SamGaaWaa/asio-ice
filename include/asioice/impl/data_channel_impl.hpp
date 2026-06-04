#pragma once

#include "asioice/config.hpp"
#include "asioice/sctp_transport.hpp"
#include "asioice/concepts.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/shared_promise.hpp"
#include "asioice/detail/detached_with_data.hpp"
#include "asioice/detail/if_else.hpp"
#include "asioice/detail/stop_when.hpp"
#include "asioice/detail/async_queue.hpp"
#include "asioice/detail/async_mutex.hpp"

#include <exec/async_scope.hpp>
#include <exec/repeat_until.hpp>

#include <boost/compat/move_only_function.hpp>
#include <boost/container/flat_map.hpp>

#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <iostream>

namespace asioice::impl {

struct data_channel_message {
    std::vector<uint8_t> data;
    bool binary;
};

template <class Sctp>
class data_channel_manager_impl
    : public std::enable_shared_from_this<data_channel_manager_impl<Sctp>> {
    static constexpr uint32_t kPpidDcep = 50;
    static constexpr uint32_t kPpidString = 51;
    static constexpr uint32_t kPpidBinary = 53;
    static constexpr uint8_t kDcepOpen = 0x03;
    static constexpr uint8_t kDcepAck = 0x02;
    static constexpr uint8_t kChannelTypeReliable = 0x00;

  public:
    using sctp_type = Sctp;

    struct data_channel : std::enable_shared_from_this<data_channel> {
        enum state_t : char { connecting, open, closing, closed };

        data_channel(
            std::shared_ptr<data_channel_manager_impl> manager) noexcept
            : _manager(std::move(manager)) {}
        data_channel(std::shared_ptr<data_channel_manager_impl> manager,
                     uint16_t sid, std::string label) noexcept
            : _manager(std::move(manager)), _stream_id(sid),
              _label(std::move(label)) {}

        data_channel(const data_channel &) = delete;
        data_channel &operator=(const data_channel &) = delete;
        data_channel(data_channel &&) = delete;
        data_channel &operator=(data_channel &&) = delete;

        ~data_channel();

        const std::string &label() const noexcept { return _label; }
        uint16_t stream_id() const noexcept { return _stream_id; }
        state_t state() const noexcept { return _state; }

        auto send(std::span<const uint8_t> data, bool binary);
        auto send_binary(std::span<const uint8_t> data);
        auto send_text(std::string_view text);
        auto read();

      private:
        friend class data_channel_manager_impl;

        static std::shared_ptr<data_channel>
        make_channel(std::shared_ptr<data_channel_manager_impl> manager,
                     uint16_t sid, std::string label) {
            return std::make_shared<data_channel>(std::move(manager), sid,
                                                  std::move(label));
        }

        static std::shared_ptr<data_channel>
        make_channel(std::shared_ptr<data_channel_manager_impl> manager) {
            return std::make_shared<data_channel>(std::move(manager));
        }

        void set_state(state_t s) noexcept { _state = s; }

        void notify_data_received() { _wait_data.set_value(); }

        std::shared_ptr<data_channel_manager_impl> _manager;
        uint16_t _stream_id = 0;
        std::string _label;
        state_t _state = state_t::connecting;
        utils::async_mutex _mutex;
        asioice::shared_promise<void> _wait_data{};
    };

    using channel_callback =
        boost::compat::move_only_function<void(std::shared_ptr<data_channel>)>;

    data_channel_manager_impl(std::shared_ptr<sctp_type> sctp)
        : _sctp(std::move(sctp)) {
        if (!_sctp)
            throw std::invalid_argument("sctp transport is null");
    }

    void start() {
        asio2exec::basic_scheduler<typename sctp_type::executor_type> sched{
            _sctp->get_executor()};
        utils::detached_with_data(
            utils::stop_when(stdexec::starts_on(sched, _read_loop()),
                             _stop_promise.get_future()),
            this->shared_from_this());
    }

    void stop() noexcept { _stop_promise.set_value(); }

    const std::shared_ptr<sctp_type> &sctp() noexcept { return _sctp; }

    std::size_t max_cache_message_count() const noexcept { return 128; }

    void on_remote_channel(channel_callback cb) {
        _on_remote_channel = std::move(cb);
    }

    task<std::shared_ptr<data_channel>>
    create_data_channel(std::string label, bool ordered = true) {
        auto ch = data_channel::make_channel(
            this->shared_from_this(), _next_stream_id++, std::move(label));
        _channels[ch->stream_id()] = ch.get();

        co_await _send_dcep_open(*ch, ordered);
        ch->set_state(data_channel::state_t::open);
        co_return ch;
    }

    auto send(const data_channel &ch, std::span<const uint8_t> data,
              bool binary) {
        uint32_t ppid = binary ? kPpidBinary : kPpidString;
        exsctp::message msg{ch.stream_id(), ppid, data};
        return stdexec::just(std::move(msg)) |
               stdexec::let_value([this](exsctp::message &msg) {
                   return _sctp->send(msg, exsctp::send_options{});
               });
    }

    task<bool> send_text(const data_channel &ch, std::string_view text) {
        return send(
            ch,
            std::span<const uint8_t>{
                reinterpret_cast<const uint8_t *>(text.data()), text.size()},
            false);
    }

  private:
    asioice::task<bool> _send_dcep_open(const data_channel &ch, bool ordered) {
        uint8_t channel_type = ordered ? kChannelTypeReliable : uint8_t(0x01);
        size_t msg_len = 12 + ch._label.size();
        std::vector<uint8_t> buf(msg_len, 0);
        buf[0] = kDcepOpen;
        buf[1] = channel_type;
        uint16_t label_len = uint16_t(ch.label().size());
        buf[8] = uint8_t(label_len >> 8);
        buf[9] = uint8_t(label_len & 0xFF);
        std::memcpy(buf.data() + 12, ch.label().data(), ch.label().size());

        exsctp::message msg{ch.stream_id(), kPpidDcep, buf};
        co_return co_await _sctp->send(msg, exsctp::send_options{});
    }

    task<void> _handle_dcep(uint16_t sid, std::span<const uint8_t> data) {
        if (data.size() < 1)
            co_return;
        uint8_t msg_type = data[0];

        if (msg_type == kDcepOpen && data.size() >= 12) {
            uint16_t label_len = (uint16_t(data[8]) << 8) | data[9];
            uint16_t proto_len = (uint16_t(data[10]) << 8) | data[11];
            if (data.size() < size_t(12) + label_len + proto_len) {
                ICE_IN_DEBUG {
                    std::cerr
                        << "Invalid DCEP OPEN message: insufficient length\n";
                }
                co_return;
            }

            auto ch = data_channel::make_channel(this->shared_from_this());
            ch->_label = std::string(
                reinterpret_cast<const char *>(data.data() + 12), label_len);
            ch->_stream_id = sid;
            _channels[sid] = ch.get();
            ch->set_state(data_channel::state_t::open);

            // ACK is sent on the same stream as the OPEN
            uint8_t ack = kDcepAck;
            exsctp::message ack_msg{sid, kPpidDcep,
                                    std::span<const uint8_t>{&ack, 1}};
            co_await _sctp->send(ack_msg, exsctp::send_options{});

            if (_on_remote_channel)
                _on_remote_channel(ch);
        }
    }

    task<void> _read_loop() {
        while (!_stopped) {
            auto opt = co_await _sctp->read();
            if (!opt)
                break;
            auto ppid = opt->ppid();
            auto sid = opt->stream_id();
            auto payload = std::move(*opt).ReleasePayload();

            if (*ppid == kPpidDcep) {
                co_await _handle_dcep(*sid, payload);
            } else {
                while (_received_messages.size() >
                       this->max_cache_message_count()) {
                    co_await _not_full.get_future();
                }
                _received_messages.emplace(
                    *sid, data_channel_message{std::move(payload),
                                               *ppid == kPpidBinary});
                auto it = _waiting_channels.find(*sid);
                if (it != _waiting_channels.end()) {
                    auto ch = it->second;
                    _waiting_channels.erase(it);
                    ch->notify_data_received();
                }
            }
        }
    }

    std::shared_ptr<sctp_type> _sctp;
    bool _stopped{false};
    asioice::shared_promise<void> _stop_promise{};
    uint16_t _next_stream_id{0};
    channel_callback _on_remote_channel;
    boost::container::flat_map<uint16_t, data_channel *> _channels{};

    // recv
    boost::container::flat_multimap<uint16_t, data_channel_message>
        _received_messages{};
    boost::container::flat_map<uint16_t, data_channel *> _waiting_channels{};
    asioice::shared_promise<void> _not_full{};
};

template <class Sctp>
data_channel_manager_impl<Sctp>::data_channel::~data_channel() {
    this->_manager->_channels.erase(this->stream_id());
    this->_manager->_waiting_channels.erase(this->stream_id());
}

template <class Sctp>
auto data_channel_manager_impl<Sctp>::data_channel::send(
    std::span<const uint8_t> data, bool binary) {
    return this->_manager->send(*this, data, binary);
}

template <class Sctp>
auto data_channel_manager_impl<Sctp>::data_channel::send_binary(
    std::span<const uint8_t> data) {
    return this->send(data, true);
}

template <class Sctp>
auto data_channel_manager_impl<Sctp>::data_channel::send_text(
    std::string_view text) {
    return this->send(
        std::span<const uint8_t>{reinterpret_cast<const uint8_t *>(text.data()),
                                 text.size()},
        false);
}

template <class Sctp>
auto data_channel_manager_impl<Sctp>::data_channel::read() {
    uint16_t sid = this->stream_id();

    auto work =
        stdexec::just(std::optional<data_channel_message>{}) |
        stdexec::let_value([this, sid](auto &res) {
            return stdexec::just() | stdexec::let_value([&] {
                       auto it = this->_manager->_received_messages.find(sid);
                       if (it != this->_manager->_received_messages.end()) {
                           std::size_t n =
                               this->_manager->_received_messages.size();
                           res = std::move(it->second);
                           this->_manager->_received_messages.erase(it);
                           if (n == this->_manager->max_cache_message_count()) {
                               this->_manager->_not_full.set_value();
                           }
                       }
                       return utils::if_else(
                           stdexec::just(res.has_value()),
                           [] { return stdexec::just(true); },
                           [this, sid] {
                               this->_manager->_waiting_channels[sid] = this;
                               return this->_wait_data.get_future() |
                                      stdexec::then([] { return false; });
                           });
                   }) |
                   exec::repeat_until() |
                   stdexec::then([&] { return std::move(res); }) |
                   stdexec::upon_stopped(
                       [&] { return std::optional<data_channel_message>{}; });
        });

    return this->_mutex.lock() |
           stdexec::let_value([work = std::move(work)](auto &lk) mutable {
               return std::move(work);
           });
}

} // namespace asioice::impl