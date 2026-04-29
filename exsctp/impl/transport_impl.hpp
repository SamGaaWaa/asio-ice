#pragma once

#include "config.hpp"
#include "utils/async_mutex.hpp"
#include "utils/async_queue.hpp"
#include "utils/shared_promise.hpp"
#include "utils/detached_with_data.hpp"
#include "utils/stop_when.hpp"
#include "utils/scope_guard.hpp"
#include "option.hpp"
#include "message.hpp"

#include "dcsctp-packet/packet/sctp_packet.h"
#include "dcsctp-packet/packet/data.h"
#include "dcsctp-packet/packet/chunk/sack_chunk.h"

#include <boost/container/flat_map.hpp>
#include <boost/intrusive/set.hpp>
#include <boost/intrusive/list.hpp>

#include <algorithm>
#include <cassert>
#include <memory>
#include <vector>
#include <deque>
#include <ranges>

namespace exsctp::impl {

template <class Interface>
struct transport_impl: std::enable_shared_from_this<transport_impl<Interface>> {
    transport_impl() = default;

    transport_impl(const transport_impl&) = delete;
    transport_impl& operator=(const transport_impl&) = delete;
    transport_impl(transport_impl&&) = delete;
    transport_impl& operator=(transport_impl&&) = delete;

    ~transport_impl();

    void start() noexcept {
        start_t3_timer();
        start_send_loop();
    }

    void stop() noexcept;

    exsctp::inline_task<std::tuple<std::error_code, std::size_t>>
    send_message(const exsctp::message& msg, const exsctp::send_options& options);

    void set_input(std::span<const uint8_t> data);
private:
    struct send_queue_hook_tag;
    struct fsn_set_hook_tag;

    using send_queue_hook = boost::intrusive::list_base_hook<
            boost::intrusive::tag<send_queue_hook_tag>,
            boost::intrusive::link_mode<boost::intrusive::auto_unlink>
        >;
    using fsn_set_hook = boost::intrusive::set_base_hook<
            boost::intrusive::tag<fsn_set_hook_tag>,
            boost::intrusive::link_mode<boost::intrusive::auto_unlink>
        >;
    struct send_item: std::enable_shared_from_this<send_item>, send_queue_hook, fsn_set_hook
    {
        enum state_t {
            pending,
            sent,
            acked,
            failed
        };

        send_item(dcsctp::Data data, transport_impl &impl) noexcept
            : data(std::move(data)), impl(impl)
        {
            impl._send_queue_total_bytes += this->data.size() + sizeof(send_item);
        }

        send_item(const send_item&) = delete;
        send_item& operator=(const send_item&) = delete;
        send_item(send_item&&) = delete;
        send_item& operator=(send_item&&) = delete;

        ~send_item() {
            if (this->state() == sent)
                impl._flight_size -= this->binary_size();
            impl._send_queue_total_bytes -= this->data.size() + sizeof(send_item);
            impl._on_send_queue_has_space.set_value();
        }

        uint32_t fsn() const noexcept {
            return this->data.fsn.value();
        }

        std::size_t binary_size() const noexcept {
            std::size_t res = this->data.size() + 16; // 16 bytes for DATA chunk header
            if (res % 4 != 0)
                res += 4 - (res % 4);
            return res;
        }

        state_t state() const noexcept {
            return _state;
        }

        void set_state(state_t new_state) noexcept;

        auto send_time() const noexcept {
            return _sent_time;
        }

        dcsctp::Data data;
        transport_impl &impl{nullptr};
        std::shared_ptr<send_item> self{nullptr};

        struct fsn_key {
            using result_type = uint32_t;
            result_type operator()(const send_item& item) const {
                return item.data.fsn.value();
            }
        };
    private:
        state_t _state{pending};
        std::chrono::steady_clock::time_point _sent_time{};
    };

    using send_queue_type = boost::intrusive::list<
            send_item, boost::intrusive::base_hook<send_queue_hook>
        >;
    using fsn_set_type = boost::intrusive::set<
            send_item, boost::intrusive::base_hook<fsn_set_hook>,
            boost::intrusive::key_of_value<typename send_item::fsn_key>,
            boost::intrusive::constant_time_size<false>>;

    exsctp::inline_task<void> bundled_send(const dcsctp::Data& data, bool delay = true);
    exsctp::inline_task<void> send_loop();
    void start_send_loop();
    void wakeup_send_loop() { _wakeup_send_loop.set_value(); }
    exsctp::inline_task<void> retransmission_loop();
    void start_t3_timer();
    void restart_t3_timer() noexcept { _on_sack.set_value(); }
    std::chrono::milliseconds calculate_rto() const noexcept;
    void get_retransmissions(std::vector<std::shared_ptr<send_item>>& result, bool is_timeout = false) const;

    void handle_sack(std::span<const uint8_t> data);
    void handle_cum_tsn_ack(uint32_t cum_tsn_ack) noexcept;
    void handle_gap_ack_blocks(dcsctp::TSN cum_tsn, std::span<const dcsctp::SackChunk::GapAckBlock>) noexcept;
    void adjust_rwnd(const dcsctp::SackChunk& sack) noexcept;

    std::shared_ptr<Interface> _interface;
    bool _is_open{true};
    const dcsctp::DcSctpOptions _options;
    uint32_t _fsn{0};
    boost::container::flat_map<uint16_t, uint16_t> _stream_ssn_map{};

    // sender side state
    utils::async_mutex _mutex{};
    exsctp::async_queue<std::shared_ptr<send_item>> _ready_queue{};
    send_queue_type _send_queue{};
    fsn_set_type _fsn_to_item{};
    uint32_t _max_sent_fsn{0};
    std::size_t _send_queue_total_bytes{0};
    std::size_t _flight_size{0};
    std::size_t _cwnd{0};
    std::size_t _a_rwnd{0};
    exsctp::shared_promise<void> _on_send_queue_has_space{};
    exsctp::shared_promise<void> _on_sack{};
    bool _send_loop_running{false};
    exsctp::shared_promise<void> _wakeup_send_loop{};
    exsctp::shared_promise<void> _stop_send_loop{};
    bool _retransmission_loop_running{false};
    exsctp::shared_promise<void> _stop_retransmission_loop{};
};

} // namespace exsctp::impl

#include "impl/transport_impl.ipp"