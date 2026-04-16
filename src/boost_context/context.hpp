#pragma once

#include <boost/context/fiber.hpp>

namespace asioice::boost_context {

struct context {
    context() noexcept = default;

    template <class Func, class... Args> context(Func &&func, Args &&...args) {
        _c = boost::context::fiber(
            [this, f = std::forward<Func>(func),
             ... args = std::forward<Args>(args)](
                boost::context::fiber &&c) mutable noexcept {
#if (defined(BOOST_USE_UCONTEXT) || defined(BOOST_USE_WINFIB))
                std::move(c).resume();
#endif
                try {
                    std::move(f)(std::move(args)...);
                } catch (...) {
                }
                assert(!_c);
                assert(_caller);
                assert(_caller->_c);
                context *caller = _caller;
                delete this;
                set_active(caller);
                return std::move(caller->_c);
            });
#if (defined(BOOST_USE_UCONTEXT) || defined(BOOST_USE_WINFIB))
        _c = std::move(_c).resume();
#endif
    }

    context(const context &) = delete;
    context &operator=(const context &) = delete;
    context(context &&) noexcept = delete;
    context &operator=(context &&) noexcept = delete;

    static context *active();

    void resume();

    static void yield();

    void set_active(context *ctx);

  private:
    boost::context::fiber _c{};
    context *_caller{nullptr};
};

template <class Func, class... Args>
inline context *make_context(Func &&func, Args &&...args) {
    return new context(std::forward<Func>(func), std::forward<Args>(args)...);
}

} // namespace asioice::boost_context