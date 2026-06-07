#pragma once

#include <exec/task.hpp>

namespace mdns {

template <class T>
using inline_task = exec::basic_task<T, exec::__task::inline_task_context<T>>;

} // namespace mdns