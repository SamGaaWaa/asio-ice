#pragma once

#include "asioice/config.hpp"
#include "asioice/detail/shared_promise.hpp"

#include <boost/intrusive/list.hpp>

namespace asioice::impl {

template <class Op> struct op_queue {
    using value_type =
        boost::intrusive::list<Op, boost::intrusive::constant_time_size<true>>;

    auto &queue() noexcept { return _q; }

    const auto &queue() const noexcept { return _q; }

    bool empty() const noexcept { return _q.empty(); }

    void push_back(Op &op) noexcept {
        _q.push_back(op);
        _promise.set_value();
    }

    void get_operations(value_type &result) noexcept {
        result.splice(result.end(), _q);
    }

    auto wait() noexcept { return _promise.get_future(); }

  private:
    value_type _q{};
    asioice::shared_promise<void> _promise{};
};

} // namespace asioice::impl