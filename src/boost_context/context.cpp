#include "boost_context/context.hpp"

#include <stdexcept>

namespace ice::boost_context {

struct context_initializer {
    static thread_local context *   active;
    static thread_local std::size_t counter;

    context_initializer() {
        if (0 == counter++) {
            initialize();
        }
    }

    ~context_initializer() {
        if (0 == --counter) {
            deinitialize();
        }
    }

    void initialize()
    {
        // main fiber context of this thread
        active = new context{};
    }

    void deinitialize()
    {
        delete active;
    }
};

// zero-initialization
thread_local context * context_initializer::active{ nullptr };
thread_local std::size_t context_initializer::counter{ 0 };

context *context::active() {
    static thread_local context_initializer initializer;
    return context_initializer::active;
}

void context::resume() {
    static thread_local context_initializer initializer;
    context * prev = this;
    // context_initializer::active_ will point to `this`
    // prev will point to previous active context
    std::swap(context_initializer::active, prev);
    _caller = prev;
    // pass pointer to the context that resumes `this`
    std::move(_c).resume_with([prev](boost::context::fiber && c){
                prev->_c = std::move( c);
                return boost::context::fiber{};
            });
}

void context::yield() {
    context *current = context_initializer::active;
    if (!current->_caller) {
        throw std::runtime_error("yield in main context");
    }
    context *caller = std::exchange(current->_caller, nullptr);
    context_initializer::active = caller;
    std::move(caller->_c).resume_with([current](boost::context::fiber && c) {
        current->_c = std::move(c);
        return boost::context::fiber{};
    });
}

void context::set_active(context *ctx) {
    static thread_local context_initializer initializer;
    context_initializer::active = ctx;
}

} // namespace ice::boost_context