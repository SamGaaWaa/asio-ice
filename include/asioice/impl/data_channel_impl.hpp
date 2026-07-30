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
#include "asioice/detail/binary.hpp"
#include "asioice/impl/data_channel_types.hpp"
#include "samlog.hpp"

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
#include <ranges>
#include <bit>

namespace asioice::impl {

template <class Sctp>
class data_channel_manager_impl
    : public std::enable_shared_from_this<data_channel_manager_impl<Sctp>> {
    static constexpr uint32_t kPpidDcep = 50;
    static constexpr uint32_t kPpidString = 51;
    static constexpr uint32_t kPpidBinary = 53;
    static constexpr uint32_t kPpidStringEmpty = 56;
    static constexpr uint32_t kPpidBinaryEmpty = 57;

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
        enum struct state_t : char { connecting, open, closing, closed };

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
            _q.clear();
            _manager->_not_full.set_one_value();
            if (state() != state_t::closed)
                request_reset();
        }

        executor_type get_executor() const noexcept {
            return _manager->get_executor();
        }

        uint16_t stream_id() const noexcept { return _stream_id; }
        const std::string &label() const noexcept { return _label; }
        const std::string &protocol() const noexcept { return _protocol; }
        bool ordered() const noexcept { return _ordered; }
        state_t state() const noexcept { return _state.get(); }
        data_channel_priority priority() const noexcept { return _priority; }
        data_channel_options options() const noexcept {
            return {.ordered = ordered(),
                    .max_packet_life_time = _max_packet_life_time,
                    .max_retransmits = _max_retransmits,
                    .protocol = protocol(),
                    .negotiated = _negotiated,
                    .stream_id = stream_id(),
                    .priority = priority()};
        }
        bool is_open() const noexcept { return state() != state_t::closed; }

        auto send(std::span<const uint8_t> data, bool is_binary) {
            uint32_t type = [=] {
                if (is_binary)
                    return data.empty() ? kPpidBinaryEmpty : kPpidBinary;
                else
                    return data.empty() ? kPpidStringEmpty : kPpidString;
            }();
            return utils::if_else(
                stdexec::just(_state == state_t::closing ||
                              _state == state_t::closed),
                [] { return stdexec::just(false); },
                [=, this] { return _manager->send(*this, data, type); });
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
                               return utils::if_else(
                                          stdexec::just(state() ==
                                                        state_t::closed),
                                          [] {
                                              return stdexec::just_stopped() |
                                                     stdexec::then([] {});
                                          },
                                          [this] {
                                              return _wait_data.get_future();
                                          }) |
                                      stdexec::continues_on(
                                          utils::basic_scheduler<executor_type>{
                                              get_executor()}) |
                                      stdexec::then([this] {
                                          assert(!_q.empty());
                                          auto msg = std::move(_q.front());
                                          _q.pop_front();
                                          _manager->dec_cache_bytes(
                                              msg.data.size());
                                          _manager->_not_full.set_one_value();
                                          return msg;
                                      });
                           },
                           [this] {
                               auto msg = std::move(_q.front());
                               _q.pop_front();
                               _manager->dec_cache_bytes(msg.data.size());
                               _manager->_not_full.set_one_value();
                               return stdexec::just(std::move(msg));
                           });
                   });
        }

        auto close() {
            request_close();
            return utils::if_else(
                stdexec::just(_state == state_t::closed),
                [] { return stdexec::just(true); },
                [this] {
                    return on_state_changed() | stdexec::then([this] {
                               return _state == state_t::closed;
                           });
                });
        }

      private:
        friend class data_channel_manager_impl;

        static std::shared_ptr<data_channel>
        make_channel(std::shared_ptr<data_channel_manager_impl> manager) {
            return std::make_shared<data_channel>(std::move(manager));
        }

        void set_state(state_t s) noexcept {
            _state = s;
            if (_state == state_t::closed)
                _wait_data.set_stopped();
        }

        void request_reset() noexcept {
            dcsctp::StreamID id{_stream_id};
            _manager->_sctp->socket().ResetStreams({&id, 1});
        }

        void request_close() noexcept {
            if (_state == state_t::closing || _state == state_t::closed)
                return;
            _state = state_t::closing;
            if (_manager->_sctp->socket().buffered_amount(
                    dcsctp::StreamID(_stream_id)) == 0) {
                request_reset();
                return;
            }
            _manager->_sctp->socket().SetBufferedAmountLowThreshold(
                dcsctp::StreamID(_stream_id), 0);
        }

        void set_attributes(const data_channel_options &options) noexcept {
            _ordered = options.ordered;
            _max_retransmits = options.max_retransmits;
            _max_packet_life_time = options.max_packet_life_time;
            _protocol = options.protocol;
            _negotiated = options.negotiated;
            _stream_id = options.stream_id;
            _priority = options.priority;
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
                   stdexec::continues_on(utils::basic_scheduler<executor_type>{
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
        data_channel_priority _priority = data_channel_priority::low;
    };

    using channel_callback =
        boost::compat::move_only_function<void(std::shared_ptr<data_channel>)>;

    data_channel_manager_impl(std::shared_ptr<sctp_type> sctp, bool is_client)
        : _sctp(std::move(sctp)),
          _sctp_metrics(_sctp->socket().GetMetrics().value()),
          _is_client(is_client), _next_stream_id(is_client ? 0 : 1) {
        if (!_sctp)
            throw std::invalid_argument("sctp transport is null");
        _sctp->on_outgoing_reseted(std::bind_front(
            &data_channel_manager_impl::on_outgoing_reseted, this));
        _sctp->on_incoming_reseted(std::bind_front(
            &data_channel_manager_impl::on_incoming_reseted, this));
        _sctp->on_buffered_amount_low(std::bind_front(
            &data_channel_manager_impl::on_buffered_amount_low, this));
    }

    data_channel_manager_impl(const data_channel_manager_impl &) = delete;
    data_channel_manager_impl(data_channel_manager_impl &&) = delete;
    data_channel_manager_impl &
    operator=(const data_channel_manager_impl &) = delete;
    data_channel_manager_impl &operator=(data_channel_manager_impl &&) = delete;

    ~data_channel_manager_impl() { assert(_cache_bytes == 0); }

    executor_type get_executor() const noexcept {
        return _sctp->get_executor();
    }

    void start() {
        utils::basic_scheduler<typename sctp_type::executor_type> sched{
            _sctp->get_executor()};
        utils::detached_with_data(
            utils::stop_when(stdexec::starts_on(sched, read_loop()),
                             _stop_promise.get_future() |
                                 stdexec::continues_on(sched)),
            this->shared_from_this());
    }

    void stop() noexcept {
        _sctp->on_outgoing_reseted(nullptr);
        _sctp->on_incoming_reseted(nullptr);
        _sctp->on_buffered_amount_low(nullptr);
        _stop_promise.set_value();
        _on_remote_channel = nullptr;
        while (!_channels.empty()) {
            auto &ch = *_channels.begin()->second;
            _channels.erase(_channels.begin());
            ch.set_state(data_channel::state_t::closed);
        }
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
    create_data_channel(std::string label, data_channel_options options,
                        auto...) {
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
        _sctp->socket().SetStreamPriority(
            dcsctp::StreamID(ch->stream_id()),
            dcsctp::StreamPriority((uint16_t)ch->priority()));
        co_return ch;
    }

  private:
    void on_outgoing_reseted(std::span<const dcsctp::StreamID> ids,
                             bool success, std::string_view reason) {
        if (!success) {
            SAMLOG_DEBUG(auto sink) {
                char buf[256];
                for (auto id : ids)
                    sink({buf, sizeof(buf)}, "Reset stream {} failed\n", *id);
            };
            // fallthrough
        }
        for (const auto &id : ids) {
            auto it = _channels.find(*id);
            if (it == _channels.end())
                continue;
            it->second->set_state(data_channel::state_t::closed);
        }
    }

    void on_incoming_reseted(std::span<const dcsctp::StreamID> ids) {
        for (const auto &id : ids) {
            auto it = _channels.find(*id);
            if (it == _channels.end())
                continue;
            it->second->request_close();
        }
    }

    void on_buffered_amount_low(dcsctp::StreamID id) {
        auto it = _channels.find(*id);
        if (it == _channels.end())
            return;
        if (it->second->state() == data_channel::state_t::closing) {
            it->second->request_reset();
        }
    }

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
            SAMLOG_DEBUG(auto sink) { sink("Unknown datachannel type\n"); };
            break;
        }
        return options;
    }

    auto send_dcep_open(const data_channel &ch) {
        size_t msg_len = 12 + ch.label().size() + ch.protocol().size();
        std::vector<uint8_t> buf(msg_len, 0);

        buf[0] = kDcepOpen;
        buf[1] = ch.get_channel_type();
        binary::write_big<uint16_t, 2>(buf.data(), (uint16_t)ch.priority());
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
                SAMLOG_WARN(auto sink) {
                    sink("(_is_client && (sid % 2) == 0) || (!_is_client && "
                         "(sid % 2) != 0) || _channels.contains(sid)\n");
                };
                co_return;
            }
            uint16_t label_len = binary::read_big<uint16_t, 8>(data.data());
            uint16_t proto_len = binary::read_big<uint16_t, 10>(data.data());
            if (data.size() < size_t(12) + label_len + proto_len) {
                SAMLOG_WARN(auto sink) {
                    sink("Invalid DCEP OPEN message: insufficient length\n");
                };
                co_return;
            }

            auto opt = parse_reliability_options(data);
            if (opt.max_packet_life_time && opt.max_retransmits) {
                SAMLOG_WARN(auto sink) {
                    sink("Invalid open options: max_packet_life_time "
                         "&& max_retransmits\n");
                };
                co_return;
            }
            switch (auto pri = binary::read_big<uint16_t, 2>(data.data());
                    pri) {
            case std::to_underlying(data_channel_priority::very_low):
            case std::to_underlying(data_channel_priority::low):
            case std::to_underlying(data_channel_priority::medium):
            case std::to_underlying(data_channel_priority::high):
                opt.priority = static_cast<data_channel_priority>(pri);
                break;
            default:
                SAMLOG_DEBUG(auto sink) {
                    char buf[256];
                    sink({buf, sizeof(buf)}, "unknown priority: {}\n", pri);
                };
                opt.priority = data_channel_priority::low;
                break;
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
            ch->_priority = opt.priority;

            // ACK is sent on the same stream as the OPEN
            uint8_t ack = kDcepAck;
            exsctp::message ack_msg{sid, kPpidDcep,
                                    std::span<const uint8_t>{&ack, 1}};
            bool acked = co_await _sctp->send(ack_msg, exsctp::send_options{});
            if (!acked) {
                SAMLOG_DEBUG(auto sink) {
                    sink("Failed to send a DATA_CHANNEL_ACK Message\n");
                };
                co_return;
            }
            _channels[sid] = ch.get();
            ch->set_state(data_channel::state_t::open);
            _next_stream_id = sid + 1;

            _sctp->socket().SetStreamPriority(
                dcsctp::StreamID(ch->stream_id()),
                dcsctp::StreamPriority((uint16_t)ch->priority()));
            if (_on_remote_channel)
                _on_remote_channel(std::move(ch));
        } else if (msg_type == kDcepAck) {
            auto it = _channels.find(sid);
            if (it == _channels.end()) {
                SAMLOG_DEBUG(auto sink) {
                    sink("DATA_CHANNEL_ACK Message: unknown stream id\n");
                };
                co_return;
            }
            if (it->second->state() == data_channel::state_t::connecting)
                it->second->set_state(data_channel::state_t::open);
        }
    }

    task<void> read_loop() {
        while (!_stopped) {
            auto opt = co_await _sctp->read();
            if (!opt) {
                stop();
                break;
            }
            auto ppid = opt->ppid();
            auto sid = opt->stream_id();
            auto payload = std::move(*opt).ReleasePayload();

            if (*sid >= max_datachannel_count())
                continue;

            if (*ppid == kPpidDcep) {
                co_await handle_dcep(*sid, payload);
            } else {
                if (*ppid == kPpidStringEmpty || *ppid == kPpidBinaryEmpty) {
                    std::vector<uint8_t>{}.swap(payload);
                }
                auto it = _channels.find(*sid);
                if (it == _channels.end()) {
                    SAMLOG_DEBUG(auto sink) { sink("Unknown stream id\n"); };
                    // TODO: reset stream
                    continue;
                }
                while (_cache_bytes + payload.size() >
                       this->max_cache_bytes()) {
                    co_await (_not_full.get_future() |
                              stdexec::continues_on(
                                  utils::basic_scheduler<executor_type>{
                                      get_executor()}));
                    it = _channels.find(*sid);
                }
                if (it == _channels.end())
                    continue;
                it->second->push(data_channel_message{
                    std::move(payload),
                    *ppid == kPpidBinary || *ppid == kPpidBinaryEmpty});
            }
        }
    }

    auto send(const data_channel &ch, std::span<const uint8_t> data,
              uint32_t msg_type) {
        static const uint8_t zero = 0;
        if (data.empty())
            data = std::span<const uint8_t>(&zero, 1);
        uint32_t ppid = msg_type;
        exsctp::message msg{ch.stream_id(), ppid, data};
        return stdexec::just(std::move(msg)) |
               stdexec::let_value([this, &ch](exsctp::message &msg) {
                   return _sctp->send(msg, ch.get_send_options());
               });
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