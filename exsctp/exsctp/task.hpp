#pragma once

#include <exec/task.hpp>

namespace exsctp {

template <class T>
using inline_task = exec::basic_task<T, exec::__task::inline_task_context<T>>;

template <class T>
using task = exec::basic_task<T>;

} // namespace exsctp