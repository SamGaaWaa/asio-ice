#pragma once

#include <exec/variant_sender.hpp>

namespace asioice::utils {

template <auto... Case>
    requires(
        true && ... &&
        (std::is_integral_v<decltype(Case)> || std::is_enum_v<decltype(Case)>))
struct switch_case_t {
    static constexpr std::tuple<std::decay_t<decltype(Case)>...> cases{Case...};

    template <class Cond, class... Func>
        requires((std::is_integral_v<Cond> || std::is_enum_v<Cond>) && ... &&
                 (std::is_invocable_v<Func> &&
                  stdexec::sender<std::invoke_result_t<Func>>))
    static constexpr auto operator()(Cond cond, Func &&...func) {
        static_assert(sizeof...(Func) <= sizeof...(Case));

        using result_sender_t =
            exec::variant_sender<std::decay_t<std::invoke_result_t<Func>>...>;

        std::tuple<std::decay_t<Func>...> funcs{std::forward<Func>(func)...};
        std::optional<result_sender_t> sndr;
        [&funcs, &sndr, cond]<size_t... Idx>(std::index_sequence<Idx...>) {
            (true && ... && [&funcs, &sndr, cond] {
                constexpr auto idx = Idx;
                if (cond == std::get<idx>(cases)) {
                    sndr.emplace(std::get<idx>(funcs)());
                    return false;
                }
                return true;
            }());
        }(std::make_index_sequence<sizeof...(Func)>{});
        return std::move(sndr).value();
    }
};

template <auto... Case> inline constexpr switch_case_t<Case...> switch_case{};

} // namespace asioice::utils