#pragma once

#include <cctype>
#include <string_view>

namespace ice::utils {

bool case_insensitive_equal(std::string_view a, std::string_view b) noexcept;

std::string random_string(std::size_t n);

} // namespace ice::utils