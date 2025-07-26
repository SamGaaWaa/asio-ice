#include "boost_context/context.hpp"

#include <utility>
#include <cassert>

namespace ice::boost_context {

struct fiber_handle {
    fiber_handle() noexcept = default;

    fiber_handle(context *ctx) noexcept : _ctx(ctx) {}

    fiber_handle(const fiber_handle&) noexcept = default;
    fiber_handle(fiber_handle&&) noexcept = default;
    fiber_handle& operator=(const fiber_handle&) noexcept = default;
    fiber_handle& operator=(fiber_handle&&) noexcept = default;

    bool done() const noexcept {
        assert(_ctx);
        return _ctx->_c;
    }

    operator bool() const noexcept {
        return _ctx;
    }

    void resume();
    void operator()() { resume(); }
private:
    context *_ctx{nullptr};
};

} // namespace ice::boost_context