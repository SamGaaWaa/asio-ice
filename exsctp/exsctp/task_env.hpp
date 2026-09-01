#pragma once

#include <stdexec/execution.hpp>
#include <memory_resource>

namespace exsctp {

struct task_env : stdexec::env<> {
    using allocator_type = std::pmr::polymorphic_allocator<std::byte>;
    using start_scheduler_type = stdexec::inline_scheduler;
};

} // namespace exsctp