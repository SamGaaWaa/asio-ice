#pragma once

#include "asioice/config.hpp"
#include "asioice/sctp_transport.hpp"
#include "asioice/concepts.hpp"
#include "asioice/task.hpp"
#include "asioice/detail/shared_promise.hpp"

#include <exec/async_scope.hpp>

#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>

namespace asioice {

inline constexpr uint32_t kPpidDcep = 50;
inline constexpr uint32_t kPpidString = 51;
inline constexpr uint32_t kPpidBinary = 53;
inline constexpr uint8_t kDcepOpen = 0x03;
inline constexpr uint8_t kDcepAck = 0x02;
inline constexpr uint8_t kChannelTypeReliable = 0x00;

struct data_channel_message {
    std::vector<uint8_t> data;
    bool binary;
};

template <AsyncPacketConnectionTransport Layer>
class data_channel_manager;

class data_channel : public std::enable_shared_from_this<data_channel> {
    template <AsyncPacketConnectionTransport>
    friend class data_channel_manager;

  public:
    using state_callback = std::function<void()>;

    data_channel() = default;

    task<std::optional<data_channel_message>> async_read() {
        while (true) {
            {
                std::lock_guard lk{_mutex};
                if (!_queue.empty()) {
                    auto msg = std::move(_queue.front());
                    _queue.pop_front();
                    if (!_not_full.empty())
                        _not_full.set_value();
                    co_return msg;
                }
                if (_closed)
                    co_return std::nullopt;
            }
            co_await _not_empty.get_future();
        }
    }

    void on_open(state_callback cb) { _on_open = std::move(cb); }

    const std::string &label() const noexcept { return _label; }
    bool is_open() const noexcept { return _open; }
    uint16_t stream_id() const noexcept { return _stream_id; }

  private:
    static constexpr std::size_t kMaxQueue = 256;

    void _set_open() {
        if (!_open) {
            _open = true;
            if (_on_open)
                _on_open();
        }
    }

    task<void> _push(data_channel_message msg) {
        while (true) {
            bool should_notify = false;
            bool should_wait = false;
            {
                std::lock_guard lk{_mutex};
                if (_closed)
                    throw std::runtime_error("channel closed");
                if (_queue.size() < kMaxQueue) {
                    _queue.push_back(std::move(msg));
                    should_notify = !_not_empty.empty();
                } else {
                    should_wait = true;
                }
            }
            if (should_notify)
                _not_empty.set_value();
            if (should_wait)
                co_await _not_full.get_future();
            else
                co_return;
        }
    }

    void _close() {
        std::lock_guard lk{_mutex};
        _closed = true;
        if (!_not_empty.empty())
            _not_empty.set_value();
        if (!_not_full.empty())
            _not_full.set_value();
    }

    uint16_t _stream_id = 0;
    std::string _label;
    bool _open = false;
    state_callback _on_open;

    std::deque<data_channel_message> _queue;
    std::mutex _mutex;
    bool _closed = false;
    shared_promise<void> _not_empty;
    shared_promise<void> _not_full;
};

template <AsyncPacketConnectionTransport Layer>
class data_channel_manager {
  public:
    using sctp_type = sctp::transport<Layer>;
    using channel_callback =
        std::function<void(std::shared_ptr<data_channel>)>;

    data_channel_manager() = default;

    void start(std::shared_ptr<sctp_type> sctp, exec::async_scope &scope) {
        _sctp = std::move(sctp);
        asio2exec::basic_scheduler<typename sctp_type::executor_type>
            sched{_sctp->get_executor()};
        scope.spawn(stdexec::starts_on(sched, _read_loop()));
    }

    std::shared_ptr<sctp_type> sctp() noexcept { return _sctp; }

    void on_remote_channel(channel_callback cb) {
        _on_remote_channel = std::move(cb);
    }

    task<std::shared_ptr<data_channel>>
    create_data_channel(std::string label, bool ordered = true) {
        auto ch = std::make_shared<data_channel>();
        ch->_label = std::move(label);

        {
            std::lock_guard lk{_mutex};
            ch->_stream_id = _next_stream_id++;
            _channels[ch->_stream_id] = ch;
        }

        co_await _send_dcep_open(*ch, ordered);
        ch->_set_open();
        co_return ch;
    }

    task<bool> send(const data_channel &ch,
                    std::span<const uint8_t> data, bool binary) {
        uint32_t ppid = binary ? kPpidBinary : kPpidString;
        exsctp::message msg{ch._stream_id, ppid, data};
        bool ok = co_await _sctp->send(msg, exsctp::send_options{});
        co_return ok;
    }

    task<bool> send_text(const data_channel &ch,
                         std::string_view text) {
        return send(ch,
                    std::span<const uint8_t>{
                        reinterpret_cast<const uint8_t *>(text.data()),
                        text.size()},
                    false);
    }

    void stop() noexcept { _stopping = true; }

  private:
    task<void> _read_loop() {
        while (!_stopping) {
            auto opt = co_await _sctp->read();
            if (!opt)
                break;
            auto ppid = opt->ppid();
            auto sid = opt->stream_id();
            auto payload = std::move(*opt).ReleasePayload();

            if (*ppid == kPpidDcep) {
                co_await _handle_dcep(*sid, payload);
            } else {
                std::shared_ptr<data_channel> ch;
                {
                    std::lock_guard lk{_mutex};
                    auto it = _channels.find(*sid);
                    if (it != _channels.end())
                        ch = it->second;
                }
                if (ch)
                    co_await ch->_push(
                        data_channel_message{
                            std::move(payload),
                            *ppid == kPpidBinary});
            }
        }
    }

    task<void> _handle_dcep(uint16_t sid,
                            std::span<const uint8_t> data) {
        if (data.size() < 1)
            co_return;
        uint8_t msg_type = data[0];

        if (msg_type == kDcepOpen && data.size() >= 12) {
            uint16_t label_len = (uint16_t(data[8]) << 8) | data[9];
            uint16_t proto_len = (uint16_t(data[10]) << 8) | data[11];
            if (data.size() < size_t(12) + label_len + proto_len)
                co_return;

            auto ch = std::make_shared<data_channel>();
            ch->_label = std::string(
                reinterpret_cast<const char *>(data.data() + 12),
                label_len);

            {
                std::lock_guard lk{_mutex};
                ch->_stream_id = sid;
                _channels[sid] = ch;
            }
            ch->_set_open();

            // ACK is sent on the same stream as the OPEN
            std::vector<uint8_t> ack = {kDcepAck};
            exsctp::message ack_msg{sid, kPpidDcep, ack};
            co_await _sctp->send(ack_msg, exsctp::send_options{});

            if (_on_remote_channel)
                _on_remote_channel(ch);
        }
    }

    task<void> _send_dcep_open(const data_channel &ch,
                                bool ordered) {
        uint8_t channel_type =
            ordered ? kChannelTypeReliable : uint8_t(0x01);
        size_t msg_len = 12 + ch._label.size();
        std::vector<uint8_t> buf(msg_len, 0);
        buf[0] = kDcepOpen;
        buf[1] = channel_type;
        uint16_t label_len = uint16_t(ch._label.size());
        buf[8] = uint8_t(label_len >> 8);
        buf[9] = uint8_t(label_len & 0xFF);
        std::memcpy(buf.data() + 12, ch._label.data(),
                    ch._label.size());

        exsctp::message msg{ch._stream_id, kPpidDcep, buf};
        co_await _sctp->send(msg, exsctp::send_options{});
        co_return;
    }

    std::shared_ptr<sctp_type> _sctp;
    channel_callback _on_remote_channel;
    std::unordered_map<uint16_t, std::shared_ptr<data_channel>> _channels;
    uint16_t _next_stream_id = 1;
    std::mutex _mutex;
    bool _stopping = false;
};

} // namespace asioice
