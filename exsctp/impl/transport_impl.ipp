namespace exsctp::impl {

template <class Interface>
transport_impl<Interface>::~transport_impl()
{
    this->_stop_retransmission_loop.set_value();
    this->_stop_send_task.set_value();
    while (!_send_queue.empty()) {
        auto &item = _send_queue.front();
        _send_queue.pop_front();

        auto tmp = std::move(item.self);
        this->_fsn_to_item.erase(this->_fsn_to_item.iterator_to(item));
    }
    assert(this->_send_queue_total_bytes == 0);
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
    while (this->_send_queue_total_bytes + msg.data.size() > this->_options.max_send_buffer_size)
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
    this->_send_queue.push_back(*item);
    this->_fsn_to_item.insert(*item);
    item->self = item;
    this->send_new_data();
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
transport_impl<Interface>::send_new_data()
{
    if (!_is_open || this->_send_task_running)
        return;
    utils::detached_with_data(
        stdexec::starts_on(
            this->_interface->scheduler(),
            utils::stop_when(
                this->send_task(),
                this->_stop_send_task.get_future()
            )
        ),
        this->shared_from_this()
    );
    this->_send_task_running = true;
}

template <class Interface>
exsctp::inline_task<void>
transport_impl<Interface>::send_task()
{
    utils::scope_guard on_exit([this]()noexcept { this->_send_task_running = false; });

    using send_item = transport_impl<Interface>::send_item;
    std::vector<std::shared_ptr<send_item>> items;

    auto flight_size = this->_flight_size;
    for (auto& item: this->_send_queue) {
        if (item.state() != send_item::state_t::pending)
            continue;
        flight_size += item.data.size();
        if (flight_size > std::min(this->_a_rwnd, this->_cwnd))
            break;
        items.push_back(item.self);
    }
    for (auto& item: items) {
        co_await this->bundled_send(item->data);
        item->set_state(send_item::state_t::sent);
    }
}

template <class Interface>
exsctp::inline_task<void>
transport_impl<Interface>::retransmission_loop()
{
    utils::scope_guard on_exit([this]()noexcept { this->_retransmission_loop_running = false; });

    using send_item = transport_impl<Interface>::send_item;
    std::vector<std::shared_ptr<send_item>> items;
    while (true) {
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
        while (true) {
            auto ret = co_await utils::stop_when(
                this->_interface->scheduler_after(this->calculate_rto()),
                this->_on_sack.get_future() | stdexec::continues_on(this->_interface->scheduler())
            );
            if (ret)
                break;
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
    auto it = this->_fsn_to_item.find(cumulative_tsn_ack);
    if (it == this->_fsn_to_item.end())
        return;
    auto &acked_item = *it;
    while (true) {
        auto &item = this->_send_queue.front();
        item.set_state(transport_impl<Interface>::send_item::state_t::acked);
        this->_send_queue.pop_front();
        this->_fsn_to_item.erase(this->_fsn_to_item.iterator_to(item));

        auto tmp = std::move(item.self);
        if (&item == &acked_item)
            break;
    }
    this->handle_gap_ack_blocks(cumulative_tsn_ack, sack.gap_ack_blocks());
    this->adjust_rwnd(sack);
    this->restart_t3_timer();
    this->send_new_data();
}

template <class Interface>
void
transport_impl<Interface>::handle_gap_ack_blocks(dcsctp::TSN cum_tsn, std::span<const dcsctp::SackChunk::GapAckBlock> gap_ack_blocks) noexcept
{
    if (this->_send_queue.empty())
        return;
    for (const auto& block: gap_ack_blocks) {
        auto start_tsn = cum_tsn.value() + block.start;
        auto end_tsn = cum_tsn.value() + block.end;
        auto start_it = this->_fsn_to_item.find(start_tsn);
        auto end_it = this->_fsn_to_item.find(end_tsn);
        if (start_it == this->_fsn_to_item.end() || end_it == this->_fsn_to_item.end())
            continue;
        auto list_start_it = this->_send_queue.iterator_to(*start_it);
        auto list_end_it = this->_send_queue.iterator_to(*end_it);
        for (auto it = list_start_it; it != std::next(list_end_it); ++it) {
            auto &item = *it;
            item.set_state(transport_impl<Interface>::send_item::state_t::acked);
            this->_send_queue.erase(it);
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
        this->impl._flight_size += this->data.size();
        this->_sent_time = std::chrono::steady_clock::now();
        return;
    }
    if (this->_state == state_t::sent) {
        if (new_state == state_t::acked) {
            // TODO: RTO calculation
        }
        this->_state = new_state;
        this->impl._flight_size -= this->data.size();
        return;
    }
}

template <class Interface>
void
transport_impl<Interface>::get_retransmissions(std::vector<std::shared_ptr<send_item>>& result) const
{
    using send_item = transport_impl<Interface>::send_item;
    auto flight_size = this->_flight_size;
    for (auto& item: this->_send_queue) {
        flight_size += item.data.size();
        if (flight_size > std::min(this->_a_rwnd, this->_cwnd))
            break;
        item.set_state(send_item::state_t::pending);
        result.push_back(item.self);
    }
}

exsctp::inline_task<void> bundled_send(const dcsctp::Data& data, bool delay = true);

} // namespace exsctp::impl