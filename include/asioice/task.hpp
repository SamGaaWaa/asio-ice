#pragma once

#include <exec/task.hpp>

namespace asioice {

template <class T>
using task = exec::basic_task<T, exec::__task::inline_task_context<T>>;

} // namespace asioice