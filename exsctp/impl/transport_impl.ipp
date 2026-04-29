namespace exsctp::impl {

template <class Interface>
void transport_impl<Interface>::stop() noexcept {
    this->_is_open = false;
    this->_stop_retransmission_loop.set_value();
    this->_stop_send_loop.set_value();
    while (!this->_ready_queue.empty()) {
        auto &item = this->_ready_queue.front();
        _ready_queue.pop_front();
        auto tmp = std::move(item.self);
    }
    while (!_send_queue.empty()) {
        auto &item = _send_queue.front();
        _send_queue.pop_front();

        auto tmp = std::move(item.self);
        this->_fsn_to_item.erase(this->_fsn_to_item.iterator_to(item));
    }
    assert(this->_send_queue_total_bytes == 0);
}

template <class Interface>
transport_impl<Interface>::~transport_impl()
{

}

template <class Interface>
exsctp::inline_task<std::tuple<std::error_code, std::size_t>>
transport_impl<Interface>::send_message(
    const exsctp::message& msg,
    const exsctp::send_options& options)
{
    if (msg.data.size() > this->_options.max_message_size) {
        co_return std::make_tuple(std::make_error_code(std::errc::message_size), 0);
    }
    while (this->_send_queue_total_bytes + msg.data.size() + sizeof(transport_impl<Interface>::send_item) > this->_options.max_send_buffer_size)
        co_await (this->_on_send_queue_has_space.get_future() |
                    stdexec::continues_on(this->_interface->scheduler()));
    auto &ssn = this->_stream_ssn_map.at(msg.stream_id);
    // TODO: DATA fragmentation
    auto item = std::make_shared<transport_impl<Interface>::send_item>(
        dcsctp::Data(
            dcsctp::StreamID(msg.stream_id),
            dcsctp::SSN(ssn),
            dcsctp::MID(0), // TODO
            dcsctp::FSN(this->_fsn),
            dcsctp::PPID(msg.ppid),
            std::vector<uint8_t>(msg.data.begin(), msg.data.end()),
            dcsctp::Data::IsBeginning(true),
            dcsctp::Data::IsEnd(true),
            dcsctp::IsUnordered(options.unordered)
        ),
        *this
    );
    ssn++;
    this->_fsn++;
    this->_ready_queue.push(item);
    co_return std::make_tuple(std::error_code{}, msg.data.size());
}

template <class Interface>
void
transport_impl<Interface>::start_t3_timer()
{
    if (!_is_open || this->_retransmission_loop_running)
        return;
    utils::detached_with_data(
        stdexec::starts_on(
            this->_interface->scheduler(),
            utils::stop_when(
                this->retransmission_loop(),
                this->_stop_retransmission_loop.get_future()
            )
        ),
        this->shared_from_this()
    );
    this->_retransmission_loop_running = true;
}

template <class Interface>
void
transport_impl<Interface>::start_send_loop()
{
    if (!_is_open || this->_send_loop_running)
        return;
    utils::detached_with_data(
        stdexec::starts_on(
            this->_interface->scheduler(),
            utils::stop_when(
                this->send_loop(),
                this->_stop_send_loop.get_future()
            )
        ),
        this->shared_from_this()
    );
    this->_send_loop_running = true;
}

template <class Interface>
exsctp::inline_task<void>
transport_impl<Interface>::send_loop()
{
    using send_item = transport_impl<Interface>::send_item;
    while (this->_is_open) {
        std::optional<std::shared_ptr<send_item>> item = this->_ready_queue.try_pop();
        if (!item) {
            item = co_await (this->_ready_queue.async_pop_stoppable() | stdexec::stopped_as_optional());
            if (!item)
                co_return;
        }
        while (this->_flight_size + (*item)->binary_size() > this->_a_rwnd) {
            co_await this->_wakeup_send_loop.get_future();
        }
        co_await this->bundled_send((*item)->data);
        (*item)->set_state(send_item::state_t::sent);
        
        auto& ref = **item;
        ref.self = std::move(*item);
        this->_send_queue.push_back(ref);
        this->_fsn_to_item.insert(ref);
        this->_max_sent_fsn = ref.fsn();
    }
}

template <class Interface>
exsctp::inline_task<void>
transport_impl<Interface>::retransmission_loop()
{
    using send_item = transport_impl<Interface>::send_item;
    std::vector<std::shared_ptr<send_item>> items;
    bool timeout = false;
    while (this->_is_open) {
        items.clear();
        this->get_retransmissions(items);
        utils::scope_guard reset_state([&items]() noexcept {
            for (auto& item: items) {
                if (item->state() == send_item::state_t::sent)
                    item->set_state(send_item::state_t::failed);
            }
        });
        for (auto& item: items) {
            co_await this->bundled_send(item->data);
            item->set_state(send_item::state_t::sent);
        }
        while (this->_is_open) {
            // if (this->_send_queue.empty()) {
            //     this->wakeup_send_loop();
            // }
            auto ret = co_await utils::stop_when(
                this->_interface->scheduler_after(this->calculate_rto()),
                this->_on_sack.get_future() | stdexec::continues_on(this->_interface->scheduler())
            );
            if (ret) {
                SCTP_IN_DEBUG{ std::cout << "t3 timer expired\n"; }
                this->_cwnd = this->_options.mtu;
                timeout = true;
                break;
            }
            // t3 timer canceled
            std::erase_if(items, [](const auto& i) {
                return i->state() == send_item::state_t::acked;
            });
        }
    }
}

template <class Interface>
void
transport_impl<Interface>::set_input(std::span<const uint8_t> data)
{
    auto ret = dcsctp::SctpPacket::Parse(data, this->_options);
    if (!ret)
        return;
    auto &packet = *ret;
    for (const auto& desc: packet.descriptors()) {
        switch (desc.type) {
        case dcsctp::SackChunk::kType: {
            this->handle_sack(desc.data);
            continue;
        }
        default:
            continue;
        }
    }
}

template <class Interface>
void
transport_impl<Interface>::handle_sack(std::span<const uint8_t> data)
{
    if (this->_send_queue.empty())
        return;
    auto ret = dcsctp::SackChunk::Parse(data);
    if (!ret)
        return;
    auto& sack = *ret;
    auto cumulative_tsn_ack = sack.cumulative_tsn_ack().value();
    this->handle_cum_tsn_ack(cumulative_tsn_ack);
    this->handle_gap_ack_blocks(cumulative_tsn_ack, sack.gap_ack_blocks());
    this->adjust_rwnd(sack);
    this->_on_send_queue_has_space.set_value();
    this->restart_t3_timer();
    this->wakeup_send_loop();
}

template <class Interface>
void
transport_impl<Interface>::handle_cum_tsn_ack(uint32_t cum_tsn_ack) noexcept
{
    if (this->_send_queue.empty())
        return;
    bool is_wrapped = this->_send_queue.back().fsn() < this->_send_queue.front().fsn();
    auto it = this->_send_queue.begin();
    if (is_wrapped) [[unlikely]] {
        if (cum_tsn_ack > this->_max_sent_fsn) {
            auto set_it = this->_fsn_to_item.lower_bound(cum_tsn_ack);
            if (set_it == this->_fsn_to_item.end())
                set_it = this->_fsn_to_item.begin();
            it = this->_send_queue.iterator_to(*set_it);
        } else {
            auto set_it = this->_fsn_to_item.lower_bound(cum_tsn_ack);
            if (set_it == this->_fsn_to_item.iterator_to(this->_send_queue.front())) {
                // remove all
                it = this->_send_queue.iterator_to(this->_send_queue.back());
            } else {
                it = this->_send_queue.iterator_to(*set_it);
            }
        }
    } else {
        auto set_it = this->_fsn_to_item.lower_bound(cum_tsn_ack);
        if (set_it == this->_fsn_to_item.end())
            it = this->_send_queue.iterator_to(this->_send_queue.back());
        else
            it = this->_send_queue.iterator_to(*set_it);
    }
    if (it->fsn() == cum_tsn_ack)
        it = std::next(it);
    while (this->_send_queue.begin() != it) {
        auto &item = this->_send_queue.front();
        item.set_state(transport_impl<Interface>::send_item::state_t::acked);
        this->_send_queue.pop_front();
        this->_fsn_to_item.erase(this->_fsn_to_item.iterator_to(item));

        auto tmp = std::move(item.self);
    }
}

template <class Interface>
void
transport_impl<Interface>::handle_gap_ack_blocks(dcsctp::TSN cum_tsn, std::span<const dcsctp::SackChunk::GapAckBlock> gap_ack_blocks) noexcept
{
    if (this->_send_queue.empty())
        return;
    for (const auto& block: gap_ack_blocks) {
        if (block.start >= block.end)
            continue;
        uint32_t start_tsn = cum_tsn.value() + block.start;
        uint32_t end_tsn = cum_tsn.value() + block.end;

        bool is_wrapped = this->_send_queue.back().fsn() < this->_send_queue.front().fsn();
        auto start_it = this->_send_queue.begin();
        auto end_it = this->_send_queue.begin();
        if (is_wrapped) [[unlikely]] {
            if (start_tsn > end_tsn) {
                if (end_tsn > this->_max_sent_fsn)
                    continue;
                auto set_begin_it = this->_fsn_to_item.lower_bound(start_tsn);
                if (set_begin_it == this->_fsn_to_item.end())
                    set_begin_it = this->_fsn_to_item.begin();
                auto set_end_it = this->_fsn_to_item.lower_bound(end_tsn);
                if (set_end_it == this->_fsn_to_item.iterator_to(this->_send_queue.front()))
                    set_end_it = this->_fsn_to_item.iterator_to(this->_send_queue.back());
                start_it = this->_send_queue.iterator_to(*set_begin_it);
                end_it = this->_send_queue.iterator_to(*set_end_it);
            } else {
                auto set_begin_it = this->_fsn_to_item.lower_bound(start_tsn);
                if (set_begin_it == this->_fsn_to_item.end())
                    continue;
                auto set_end_it = this->_fsn_to_item.lower_bound(end_tsn);
                if (set_end_it == this->_fsn_to_item.end())
                    set_end_it = this->_fsn_to_item.begin();
                start_it = this->_send_queue.iterator_to(*set_begin_it);
                end_it = this->_send_queue.iterator_to(*set_end_it);
            }
        } else {
            if (start_tsn > end_tsn)
                continue;
            auto set_begin_it = this->_fsn_to_item.lower_bound(start_tsn);
            if (set_begin_it == this->_fsn_to_item.end())
                continue;
            auto set_end_it = this->_fsn_to_item.lower_bound(end_tsn);
            if (set_end_it == this->_fsn_to_item.end())
                set_end_it = this->_fsn_to_item.iterator_to(this->_send_queue.back());
            start_it = this->_send_queue.iterator_to(*set_begin_it);
            end_it = this->_send_queue.iterator_to(*set_end_it);
        }
        if (end_it->fsn() == end_tsn)
            end_it = std::next(end_it);
        while (!this->_send_queue.empty() && start_it != end_it) {
            auto &item = *start_it;
            item.set_state(transport_impl<Interface>::send_item::state_t::acked);
            start_it = this->_send_queue.erase(start_it);
            this->_fsn_to_item.erase(this->_fsn_to_item.iterator_to(item));

            auto tmp = std::move(item.self);
        }
    }
}

template <class Interface>
void
transport_impl<Interface>::adjust_rwnd(const dcsctp::SackChunk& sack) noexcept
{
    this->_a_rwnd = sack.a_rwnd();
}

template <class Interface>
void transport_impl<Interface>::send_item::set_state(state_t new_state) noexcept
{
    if (this->_state == new_state)
        return;
    if (new_state == state_t::sent) {
        this->_state = new_state;
        this->impl._flight_size += this->binary_size();
        this->_sent_time = std::chrono::steady_clock::now();
        return;
    }
    if (this->_state == state_t::sent) {
        if (new_state == state_t::acked) {
            // TODO: RTO calculation
        }
        this->_state = new_state;
        this->impl._flight_size -= this->binary_size();
        return;
    }
}

template <class Interface>
void
transport_impl<Interface>::get_retransmissions(
    std::vector<std::shared_ptr<send_item>>& result,
    bool is_timeout
) const
{
    using send_item = transport_impl<Interface>::send_item;
    if (is_timeout) {
        if (!this->_send_queue.empty() &&
            this->_flight_size + this->_send_queue.front().binary_size() <= this->_a_rwnd)
        {
            result.push_back(this->_send_queue.front().self);
            this->_send_queue.front().set_state(send_item::state_t::pending);
        }
        return;
    }
    auto flight_size = this->_flight_size;
    for (auto& item: this->_send_queue) {
        flight_size += item.binary_size();
        if (flight_size > this->_a_rwnd)
            break;
        item.set_state(send_item::state_t::pending);
        result.push_back(item.self);
    }
}

exsctp::inline_task<void> bundled_send(const dcsctp::Data& data, bool delay = true);

} // namespace exsctp::impl