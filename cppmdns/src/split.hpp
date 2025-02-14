#pragma once

#include <string>
#include <string_view>
#include <ranges>

namespace mdns::utils{

constexpr decltype(auto) split(std::string_view str, char delimiter){
    return str |
            std::views::split(delimiter) |
            std::views::transform([](auto&& view){
                return std::string_view{view.begin(), view.end()};
            });
}

constexpr decltype(auto) split(std::string_view str, std::string_view delimiter){
    return str |
            std::views::split(delimiter) |
            std::views::transform([](auto&& view){
                return std::string_view{view.begin(), view.end()};
            });
}

}