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
#include "asioice/detail/scope_guard.hpp"
#include "asioice/detail/property.hpp"
#include "binary.hpp"

#include <exec/async_scope.hpp>
#include <exec/repeat_until.hpp>

#include <boost/compat/move_only_function.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/unordered/unordered_flat_map.hpp>

#include <algorithm>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <stdexcept>
#include <iostream>
#include <ranges>
#include <bit>

namespace asioice::impl {

struct data_channel_message {
    std::vector<uint8_t> data;
    bool binary;
};

struct data_channel_options {
    bool ordered = true;
    std::optional<uint32_t> max_packet_life_time{};
    std::optional<uint32_t> max_retransmits{};
    std::string protocol = "";
    bool negotiated = false;
    uint16_t stream_id = 0;
};

template <class Sctp>
class data_channel_manager_impl
    : public std::enable_shared_from_this<data_channel_manager_impl<Sctp>> {
    static constexpr uint32_t kPpidDcep = 50;
    static constexpr uint32_t kPpidString = 51;
    static constexpr uint32_t kPpidBinary = 53;
    static constexpr uint8_t kDcepOpen = 0x03;
    static constexpr uint8_t kDcepAck = 0x02;

    static constexpr uint8_t DATA_CHANNEL_RELIABLE = 0x00;
    static constexpr uint8_t DATA_CHANNEL_RELIABLE_UNORDERED = 0x80;
    static constexpr uint8_t DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT = 0x01;
    static constexpr uint8_t DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED =
        0x81;
    static constexpr uint8_t DATA_CHANNEL_PARTIAL_RELIABLE_TIMED = 0x02;
    static constexpr uint8_t DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED =
        0x82;

  public:
    using sctp_type = Sctp;
    using executor_type = typename sctp_type::executor_type;

    struct data_channel : std::enable_shared_from_this<data_channel> {
        using executor_type = typename Sctp::executor_type;
        enum state_t : char { connecting, open, closing, closed };

        data_channel(
            std::shared_ptr<data_channel_manager_impl> manager) noexcept
            : _manager(std::move(manager)) {}

        data_channel(const data_channel &) = delete;
        data_channel &operator=(const data_channel &) = delete;
        data_channel(data_channel &&) = delete;
        data_channel &operator=(data_channel &&) = delete;

        ~data_channel() {
            _manager->_channels.erase(this->stream_id());
            for (const auto &msg : _q)
                _manager->dec_cache_bytes(msg.data.size());
            _manager->_not_full.set_one_value();
        }

        executor_type get_executor() const noexcept {
            return _manager->get_executor();
        }

        uint16_t stream_id() const noexcept { return _stream_id; }
        const std::string &label() const noexcept { return _label; }
        const std::string &protocol() const noexcept { return _protocol; }
        bool ordered() const noexcept { return _ordered; }
        state_t state() const noexcept { return _state.get(); }

        auto send(std::span<const uint8_t> data, bool binary) {
            return _manager->send(*this, data, binary);
        }

        auto send_binary(std::span<const uint8_t> data) {
            return send(data, true);
        }

        auto send_text(std::string_view text) {
            return send(std::span<const uint8_t>{(const uint8_t *)text.data(),
                                                 text.size()},
                        false);
        }

        auto read() {
            return _mutex.lock() | stdexec::let_value([this](auto &lk) {
                       return utils::if_else(
                           stdexec::just(_q.empty()),
                           [this] {
                               return _wait_data.get_future() |
                                      stdexec::continues_on(
                                          asio2exec::basic_scheduler<
                                              executor_type>{get_executor()}) |
                                      stdexec::then([this] {
                                          assert(!_q.empty());
                                          auto msg = std::move(_q.front());
                                          _q.pop_back();
                                          _manager->dec_cache_bytes(
                                              msg.data.size());
                                          _manager->_not_full.set_one_value();
                                          return msg;
                                      });
                           },
                           [this] {
                               auto msg = std::move(_q.front());
                               _q.pop_back();
                               _manager->dec_cache_bytes(msg.data.size());
                               _manager->_not_full.set_one_value();
                               return stdexec::just(std::move(msg));
                           });
                   });
        }

      private:
        friend class data_channel_manager_impl;

        static std::shared_ptr<data_channel>
        make_channel(std::shared_ptr<data_channel_manager_impl> manager) {
            return std::make_shared<data_channel>(std::move(manager));
        }

        void set_state(state_t s) noexcept { _state = s; }

        void set_attributes(const data_channel_options &options) noexcept {
            _ordered = options.ordered;
            _max_retransmits = options.max_retransmits;
            _max_packet_life_time = options.max_packet_life_time;
            _protocol = options.protocol;
            _negotiated = options.negotiated;
            _stream_id = options.stream_id;
        }

        exsctp::send_options get_send_options() const noexcept {
            exsctp::send_options res{};
            if (_state.get() == state_t::connecting)
                return res;
            res.unordered = !_ordered;
            if (_max_retransmits)
                res.max_retransmissions = *_max_retransmits;
            if (_max_packet_life_time)
                res.lifetime =
                    std::chrono::milliseconds(*_max_packet_life_time);
            return res;
        }

        uint8_t get_channel_type() const noexcept {
            assert(!(_max_retransmits && _max_packet_life_time));
            uint8_t type = 0;
            if (!_ordered)
                type += 0x80;
            if (_max_retransmits)
                type += 1;
            else if (_max_packet_life_time)
                type += 2;
            return type;
        }

        uint32_t get_reliability_parameter() const noexcept {
            assert(!(_max_retransmits && _max_packet_life_time));
            if (_max_retransmits)
                return *_max_retransmits;
            if (_max_packet_life_time)
                return *_max_packet_life_time;
            return 0;
        }

        auto on_state_changed() {
            return _state.on_change() |
                   stdexec::continues_on(
                       asio2exec::basic_scheduler<executor_type>{
                           this->get_executor()});
        }

        void push(data_channel_message msg) {
            std::size_t size = msg.data.size();
            _q.emplace_back(std::move(msg));
            _manager->inc_cache_bytes(size);
            if (_q.size() == 1)
                _wait_data.set_value();
        }

        std::shared_ptr<data_channel_manager_impl> _manager;
        utils::async_mutex _mutex{};
        std::deque<data_channel_message> _q{};
        asioice::shared_promise<void> _wait_data{};

        // attributes
        std::string _label = "";
        std::string _protocol = "";
        bool _ordered = true;
        utils::property<state_t> _state{state_t::connecting};
        std::optional<uint32_t> _max_retransmits{};
        std::optional<uint32_t> _max_packet_life_time{}; // in ms
        bool _negotiated = false;
        uint16_t _stream_id = 0;
    };

    using channel_callback =
        boost::compat::move_only_function<void(std::shared_ptr<data_channel>)>;

    data_channel_manager_impl(std::shared_ptr<sctp_type> sctp, bool is_client)
        : _sctp(std::move(sctp)),
          _sctp_metrics(_sctp->socket().GetMetrics().value()),
          _is_client(is_client), _next_stream_id(is_client ? 0 : 1) {
        if (!_sctp)
            throw std::invalid_argument("sctp transport is null");
    }

    data_channel_manager_impl(const data_channel_manager_impl &) = delete;
    data_channel_manager_impl(data_channel_manager_impl &&) = delete;
    data_channel_manager_impl &
    operator=(const data_channel_manager_impl &) = delete;
    data_channel_manager_impl &operator=(data_channel_manager_impl &&) = delete;

    executor_type get_executor() const noexcept {
        return _sctp->get_executor();
    }

    void start() {
        asio2exec::basic_scheduler<typename sctp_type::executor_type> sched{
            _sctp->get_executor()};
        utils::detached_with_data(
            utils::stop_when(stdexec::starts_on(sched, read_loop()),
                             _stop_promise.get_future()),
            this->shared_from_this());
    }

    void stop() noexcept {
        _stop_promise.set_value();
        _on_remote_channel = nullptr;
    }

    const std::shared_ptr<sctp_type> &sctp() noexcept { return _sctp; }

    std::size_t max_cache_bytes() const noexcept {
        return _sctp->socket().options().max_message_size * 128;
    }

    std::size_t cache_bytes() const noexcept { return _cache_bytes; }

    void on_remote_channel(channel_callback cb) {
        _on_remote_channel = std::move(cb);
    }

    task<std::shared_ptr<data_channel>>
    create_data_channel(std::string label, data_channel_options options) {
        if (options.max_retransmits && options.max_packet_life_time)
            throw std::invalid_argument{
                "max_retransmits && max_packet_life_time"};
        if (!options.negotiated)
            options.stream_id = allocate_stream_id();
        else {
            if (_channels.contains(options.stream_id))
                throw std::invalid_argument{"stream id already exists"};
            _next_stream_id = options.stream_id + 1;
            if (_is_client) {
                if (_next_stream_id % 2)
                    ++_next_stream_id;
            } else {
                if ((_next_stream_id % 2) == 0)
                    ++_next_stream_id;
            }
        }

        auto ch = data_channel::make_channel(this->shared_from_this());
        ch->set_attributes(options);

        _channels[options.stream_id] = ch.get();

        if (!options.negotiated)
            co_await send_dcep_open(*ch);
        co_return ch;
    }

    auto send(const data_channel &ch, std::span<const uint8_t> data,
              bool binary) {
        uint32_t ppid = binary ? kPpidBinary : kPpidString;
        exsctp::message msg{ch.stream_id(), ppid, data};
        return stdexec::just(std::move(msg)) |
               stdexec::let_value([this, &ch](exsctp::message &msg) {
                   return _sctp->send(msg, ch.get_send_options());
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
    void inc_cache_bytes(std::size_t n) noexcept { _cache_bytes += n; }

    void dec_cache_bytes(std::size_t n) noexcept { _cache_bytes -= n; }

    std::size_t max_datachannel_count() const noexcept {
        auto res = std::min(_sctp_metrics.negotiated_maximum_incoming_streams,
                            _sctp_metrics.negotiated_maximum_outgoing_streams);
        if (res != 0 && (res % 2) != 0)
            --res;
        return res;
    }

    uint16_t allocate_stream_id() {
        const auto max_count = this->max_datachannel_count();
        if (_channels.size() >= max_count)
            throw std::runtime_error{"too many channels"};
        for (int i = 0; i < 10; ++i) {
            if (!_channels.contains(_next_stream_id)) {
                auto res = _next_stream_id;
                _next_stream_id = (_next_stream_id + 2) % max_count;
                return res;
            }
        }

        std::vector<uint64_t> bmap((max_count + 63) / 64);
        for (const auto &p : _channels) {
            auto id = p.first;
            auto index = id / 64;
            auto bit = id % 64;
            bmap[index] |= (0x1 << bit);
        }
        auto it = bmap.begin();
        while (true) {
            for (; it != bmap.end(); ++it) {
                if (*it != ~uint64_t{0})
                    break;
            }
            if (it == bmap.end())
                throw std::runtime_error{"too many channels"};
            int i = _is_client ? 0 : 1;
            for (; i < 64; i += 2) {
                if ((*it & (0x1 << i)) == 0)
                    break;
            }
            if (i >= 64)
                continue;
            auto idx = std::distance(bmap.begin(), it);
            auto res = static_cast<uint16_t>(idx * 64 + i);
            if (res >= max_count)
                throw std::runtime_error{"too many channels"};
            return res;
        }
        std::unreachable();
    }

    static data_channel_options
    parse_reliability_options(std::span<const uint8_t> data) noexcept {
        assert(data.size() >= 12);
        data_channel_options options{};
        uint8_t ch_type = binary::read_big<uint8_t, 1>(data.data());
        uint16_t param = binary::read_big<uint32_t, 4>(data.data());
        switch (ch_type) {
        case DATA_CHANNEL_RELIABLE:
            break;
        case DATA_CHANNEL_RELIABLE_UNORDERED:
            options.ordered = false;
            break;
        case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT:
            options.max_retransmits = param;
            break;
        case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED:
            options.ordered = false;
            options.max_retransmits = param;
            break;
        case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED:
            options.max_packet_life_time = param;
            break;
        case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED:
            options.ordered = false;
            options.max_packet_life_time = param;
            break;
        default:
            ICE_IN_DEBUG { std::cerr << "Unknown datachannel type\n"; }
            break;
        }
        return options;
    }

    auto send_dcep_open(const data_channel &ch) {
        size_t msg_len = 12 + ch.label().size() + ch.protocol().size();
        std::vector<uint8_t> buf(msg_len, 0);

        buf[0] = kDcepOpen;
        buf[1] = ch.get_channel_type();
        binary::write_big<uint32_t, 4>(buf.data(),
                                       ch.get_reliability_parameter());
        binary::write_big<uint16_t, 8>(buf.data(), uint16_t(ch.label().size()));
        binary::write_big<uint16_t, 10>(buf.data(),
                                        uint16_t(ch.protocol().size()));
        std::memcpy(buf.data() + 12, ch.label().data(), ch.label().size());
        std::memcpy(buf.data() + 12 + ch.label().size(), ch.protocol().data(),
                    ch.protocol().size());

        return stdexec::just(std::move(buf)) |
               stdexec::let_value([this, &ch](auto &buf) {
                   return stdexec::just(
                              exsctp::message{ch.stream_id(), kPpidDcep, buf}) |
                          stdexec::let_value([this](auto &msg) {
                              return _sctp->send(msg, exsctp::send_options{});
                          });
               });
    }

    task<void> handle_dcep(uint16_t sid, std::span<const uint8_t> data) {
        if (data.size() < 1)
            co_return;
        uint8_t msg_type = data[0];

        if (msg_type == kDcepOpen) {
            if (data.size() < 12) {
                co_return;
            }
            if ((_is_client && (sid % 2) == 0) ||
                (!_is_client && (sid % 2) != 0) || _channels.contains(sid)) {
                ICE_IN_DEBUG {
                    std::cerr
                        << "(_is_client && (sid % 2) == 0) || (!_is_client && "
                           "(sid % 2) != 0) || _channels.contains(sid)\n";
                }
                co_return;
            }
            uint16_t label_len = binary::read_big<uint16_t, 8>(data.data());
            uint16_t proto_len = binary::read_big<uint16_t, 10>(data.data());
            if (data.size() < size_t(12) + label_len + proto_len) {
                ICE_IN_DEBUG {
                    std::cerr
                        << "Invalid DCEP OPEN message: insufficient length\n";
                }
                co_return;
            }

            auto opt = parse_reliability_options(data);
            if (opt.max_packet_life_time && opt.max_retransmits) {
                ICE_IN_DEBUG {
                    std::cerr << "Invalid open options: max_packet_life_time "
                                 "&& max_retransmits\n";
                }
                co_return;
            }
            auto ch = data_channel::make_channel(this->shared_from_this());
            ch->_label = std::string(
                reinterpret_cast<const char *>(data.data() + 12), label_len);
            ch->_protocol = std::string(
                reinterpret_cast<const char *>(data.data() + 12 + label_len),
                proto_len);
            ch->_ordered = opt.ordered;
            ch->_max_retransmits = opt.max_retransmits;
            ch->_max_packet_life_time = opt.max_packet_life_time;
            ch->_stream_id = sid;

            // ACK is sent on the same stream as the OPEN
            uint8_t ack = kDcepAck;
            exsctp::message ack_msg{sid, kPpidDcep,
                                    std::span<const uint8_t>{&ack, 1}};
            bool acked = co_await _sctp->send(ack_msg, exsctp::send_options{});
            if (!acked) {
                ICE_IN_DEBUG {
                    std::cerr << "Failed to send a DATA_CHANNEL_ACK Message\n";
                }
                co_return;
            }
            _channels[sid] = ch.get();
            ch->set_state(data_channel::state_t::open);
            _next_stream_id = sid + 1;
            if (_on_remote_channel)
                _on_remote_channel(std::move(ch));
        } else if (msg_type == kDcepAck) {
            auto it = _channels.find(sid);
            if (it == _channels.end()) {
                ICE_IN_DEBUG {
                    std::cerr
                        << "DATA_CHANNEL_ACK Message: unknown stream id\n";
                }
                co_return;
            }
            if (it->second->state() == data_channel::state_t::connecting)
                it->second->set_state(data_channel::state_t::open);
        }
    }

    task<void> read_loop() {
        while (!_stopped) {
            auto opt = co_await _sctp->read();
            if (!opt)
                break;
            auto ppid = opt->ppid();
            auto sid = opt->stream_id();
            auto payload = std::move(*opt).ReleasePayload();

            if (*sid >= max_datachannel_count())
                continue;

            if (*ppid == kPpidDcep) {
                co_await handle_dcep(*sid, payload);
            } else {
                auto it = _channels.find(*sid);
                if (it == _channels.end()) {
                    ICE_IN_DEBUG { std::cerr << "Unknown stream id\n"; }
                    // TODO: reset stream
                    continue;
                }
                while (_cache_bytes + payload.size() >
                       this->max_cache_bytes()) {
                    co_await (_not_full.get_future() |
                              stdexec::continues_on(
                                  asio2exec::basic_scheduler<executor_type>{
                                      get_executor()}));
                    it = _channels.find(*sid);
                }
                if (it == _channels.end())
                    continue;
                it->second->push(data_channel_message{std::move(payload),
                                                      *ppid == kPpidBinary});
            }
        }
    }

    std::shared_ptr<sctp_type> _sctp;
    const dcsctp::Metrics _sctp_metrics;
    const bool _is_client;
    bool _stopped{false};
    asioice::shared_promise<void> _stop_promise{};
    uint16_t _next_stream_id;
    channel_callback _on_remote_channel;
    boost::unordered::unordered_flat_map<uint16_t, data_channel *> _channels{};

    // recv
    std::size_t _cache_bytes{0};
    asioice::shared_promise<void> _not_full{};
};

} // namespace asioice::impl