#pragma once

#include <cctype>
#include <string>
#include <string_view>

namespace asioice::utils {

bool nceq(std::string_view a, std::string_view b) noexcept;

std::string random_string(std::size_t n);

std::string dot_hex(const void *data, std::size_t n);

} // namespace asioice::utils