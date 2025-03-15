#pragma once

#include <exec/task.hpp>

namespace ice {

template<class T>
using task = exec::basic_task<T, exec::__task::__raw_task_context<T>>;

} // namespace ice