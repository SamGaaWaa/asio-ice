#pragma once

#if __cpp_lib_bitops >= 201907L
#include <bit>
#endif
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>

/*
    x64 msvc v19.34
    gcc 12.1
    clang 17.0.1
*/

namespace binary {

    namespace __detail {
        template<size_t N>
        struct fixed_string;

        template<fixed_string Fmt>
        struct unpack_t;

        template<fixed_string Fmt>
        struct pack_t;

        enum struct binary_error: char {
            ok = 0,
            out_of_range = 1
        };

        struct binary_category_t final: public std::error_category {
            const char* name()const noexcept override {
                return "binary";
            }

            const binary_category_t& operator()()const noexcept{
                return *this;
            }

            std::string message(int ev)const override {
                switch (static_cast<binary_error>(ev))
                {
                case binary_error::ok:
                    return "No error.";
                case binary_error::out_of_range:
                    return "Out of range.";
                default:
                    return "";
                }
            }
        };

        static inline const binary_category_t binary_category{};
    }

    namespace __detail {

#ifdef _WIN32
        using __ssize_t = long long;
#else
        using __ssize_t = ssize_t;
#endif

        template<class ...Ts>
        struct list {};

        using empty_list = list<>;

        template<class ...Ts>
        constexpr size_t list_size(list<Ts...>)noexcept {
            return sizeof...(Ts);
        }

        template<class ...As, class ...Bs>
        constexpr auto concat(list<As...>, list<Bs...>)noexcept->list<As..., Bs...> { return {}; }

        template<class ...As, class ...Bs>
        constexpr auto operator+(list<As...>, list<Bs...>)noexcept->list<As..., Bs...> { return {}; }

        template<class T, class ...Ts>
        constexpr auto push_back(list<Ts...>, T)noexcept->list<Ts..., T> { return {}; }

        constexpr auto pop_back(empty_list)noexcept->empty_list { return {}; }

        template<class T, class ...Ts>
        constexpr auto pop_back(list<T, Ts...>)noexcept {
            if constexpr (sizeof...(Ts) == 0)
                return empty_list{};
            else
                return list<T>{} + pop_back(list<Ts...>{});
        }

        template<class T, class ...Ts>
        constexpr auto push_front(list<Ts...>, T)noexcept->list<T, Ts...> { return {}; }

        template<class T, class ...Ts>
        constexpr auto pop_front(list<T, Ts...>)noexcept->list<Ts...> { return {}; }

        constexpr auto pop_front(empty_list)noexcept->empty_list { return {}; }

        template<class T, class T1, class ...Ts>
        constexpr bool contains(list<T1, Ts...>, T)noexcept {
            if constexpr (sizeof...(Ts) == 0) {
                return std::is_same_v<std::decay_t<T>, std::decay_t<T1>>;
            }
            else {
                return (std::is_same_v<std::decay_t<T>, std::decay_t<T1>> || ... || std::is_same_v<std::decay_t<T>, std::decay_t<Ts>>);
            }
        }

        template<class T>
        constexpr bool contains(empty_list, T)noexcept { return false; }

        template<size_t N, class T>
        constexpr auto fill_list(T)noexcept {
            if constexpr (N == 0)
                return empty_list{};
            else if constexpr (N == 1)
                return list<T>{};
            else {
                return list<T>{} + fill_list<N - 1>(T{});
            }
        }

        template<class T, class ...Ts>
        constexpr auto set_add(list<Ts...>, T)noexcept {
            if constexpr (contains(list<Ts...>{}, T{})) {
                return list<Ts...>{};
            }
            else {
                return list<Ts..., T>{};
            }
        }

        template<class T, class ...Ts>
        constexpr auto set_remove(list<Ts...>, T)noexcept {
            if constexpr (sizeof...(Ts) == 0)
                return empty_list{};
            else
                return (
                    empty_list{} + ... +
                    []()constexpr {
                        if constexpr (std::is_same_v<std::decay_t<Ts>, std::decay_t<T>>)
                            return empty_list{};
                        else
                            return list<Ts>{};
                    }()
                        );
        }

        template<class T, class ...Ts>
        constexpr auto front(list<T, Ts...>)noexcept->T { return {}; }

        template<class List>
        struct front_trait {
            using type = decltype(front(List{}));
        };

        template<class List>
        using front_t = typename front_trait<List>::type;

        template<class T, class ...Ts>
        constexpr auto back(list<T, Ts...>)noexcept {
            if constexpr (sizeof...(Ts) == 0)
                return T{};
            else {
                return back(list<Ts...>{});
            }
        }

        template<class List>
        struct back_trait {
            using type = decltype(back(List{}));
        };

        template<class List>
        using back_t = typename back_trait<List>::type;

        template<size_t N, class T, class ...Ts>
        constexpr auto get(list<T, Ts...>)noexcept {
            if constexpr (N == 0)
                return T{};
            else {
                return get<N - 1>(list<Ts...>{});
            }
        }

        template<size_t Start, size_t End>
        constexpr auto range(empty_list)noexcept->empty_list { return {}; }

        template<size_t Start, size_t End, class T, class ...Ts>
        constexpr auto range(list<T, Ts...>)noexcept {
            constexpr size_t size = sizeof...(Ts) + 1;
            if constexpr (Start >= End)
                return empty_list{};
            else if constexpr (Start < 0) {
                return range<0, End>(list<T, Ts...>{});
            }
            else if constexpr (End > size) {
                return range<Start, size>(list<T, Ts...>{});
            }
            else {
                using list_t = list<T, Ts...>;
                return[]<size_t ...Idx>(std::index_sequence<Idx...>)constexpr {
                    return (
                        empty_list{} + ... +
                        []()constexpr {
                            constexpr auto t = get<Start + Idx>(list_t{});
                            using term_t = decltype(t);
                            return list<term_t>{};
                        }()
                            );
                }(std::make_index_sequence<End - Start>{});
            }
        }

        template<size_t Start, size_t End, class ...Terms, class ...As>
        constexpr auto replace_with(list<Terms...>, list<As...>)noexcept {
            if constexpr (Start < 0)
                return replace_with<0, End>(list<Terms...>{}, list<As...>{});
            else if constexpr (End > sizeof...(Terms))
                return replace_with<Start, sizeof...(Terms)>(list<Terms...>{}, list<As...>{});
            else {
                return range<0, Start>(list<Terms...>{}) + list<As...>{} + range<End, sizeof...(Terms)>(list<Terms...>{});
            }
        }

        template<class F, class T, class ...Ts>
        constexpr size_t find_first_of(list<T, Ts...>, F)noexcept {
            if constexpr (sizeof...(Ts) == 0)
                return F{}(T{}) ? 0 : 1;
            else
                return F{}(T{}) ? 0 : (1 + find_first_of(list<Ts...>{}, F{}));
        }

        template<class T, T ...Vs>
        struct set {};

        template<class T>
        using empty_set = set<T>;

        template<class T, T ...As, T ...Bs>
        constexpr auto concat(set<T, As...>, set<T, Bs...>)noexcept->set<T, As..., Bs...> { return {}; }

        template<class T, T ...As, T ...Bs>
        constexpr auto operator+(set<T, As...>, set<T, Bs...>)noexcept->set<T, As..., Bs...> { return {}; }

        template<class T, T V, T ...Vs>
        constexpr auto push_back(set<T, Vs...>)noexcept->set<T, Vs..., V> { return {}; }

        template<class T>
        constexpr auto pop_back(empty_set<T>)noexcept->empty_set<T> { return {}; }

        template<class T, T V, T ...Vs>
        constexpr auto pop_back(set<T, V, Vs...>)noexcept {
            if constexpr (sizeof...(Vs) == 0)
                return V;
            else {
                return pop_back(set<T, Vs...>{});
            }
        }

        template<class T, T V, T ...Vs>
        constexpr auto push_front(set<T, Vs...>)noexcept->set<T, V, Vs...> { return {}; }

        template<class T, T V, T ...Vs>
        constexpr auto pop_front(set<T, V, Vs...>)noexcept->set<T, Vs...> { return {}; }

        template<class T>
        constexpr auto pop_front(empty_set<T>)noexcept->empty_set<T> { return {}; }

        template<class T, T V, T V1, T ...Vs>
        constexpr bool contains(set<T, V1, Vs...>)noexcept {
            if constexpr (sizeof...(Vs) == 0)
                return V == V1;
            else
                return ((V == V1) || ... || (V == Vs));
        }

        template<class T, T V>
        constexpr bool contains(empty_set<T>)noexcept { return false; }

        template<class T, T V, T ...Vs>
        constexpr auto set_add(set<T, Vs...>)noexcept {
            if constexpr (contains<T, V>(set<T, Vs...>{}))
                return set<T, Vs...>{};
            else
                return set<T, Vs..., V>{};
        }

        template<class T, T V, T ...Vs>
        constexpr auto set_remove(set<T, Vs...>)noexcept {
            if constexpr (sizeof...(Vs) == 0)
                return empty_set<T>{};
            else {
                return (
                    empty_set<T>{} + ... +
                    []()constexpr {
                        if constexpr (V == Vs)
                            return empty_set<T>{};
                        else
                            return set<T, Vs>{};
                    }()
                        );
            }
        }

        template<class T, T ...As, T ...Bs>
        constexpr auto set_union(set<T, As...> A, set<T, Bs...> B)noexcept {
            if constexpr (sizeof...(As) == 0)
                return B;
            else if constexpr (sizeof...(Bs) == 0)
                return A;
            else {
                using b_t = set<T, Bs...>;
                constexpr auto a_diff_b = (
                    empty_set<T>{} + ... +
                    []()constexpr {
                        if constexpr (contains<T, As>(b_t{}))
                            return empty_set<T>{};
                        else {
                            return set<T, As>{};
                        }
                    }()
                        );
                return a_diff_b + b_t{};
            }
        }

        template<class T, T ...As, T ...Bs>
        constexpr auto set_intersection(set<T, As...> A, set<T, Bs...> B)noexcept {
            if constexpr ((sizeof...(As) == 0) || (sizeof...(Bs) == 0))
                return empty_set<T>{};
            else {
                using b_t = set<T, Bs...>;
                return (
                    empty_set<T>{} + ... +
                    []()constexpr {
                        if constexpr (!contains<T, As>(b_t{}))
                            return empty_set<T>{};
                        else {
                            return set<T, As>{};
                        }
                    }()
                        );
            }
        }

        template<class T, T V, T ...Vs>
        constexpr size_t count(set<T, Vs...>)noexcept {
            if constexpr (sizeof...(Vs) == 0)
                return 0;
            else {
                return (
                    0 + ... +
                    []()constexpr {
                        if constexpr (V == Vs)
                            return 1;
                        else
                            return 0;
                    }()
                        );
            }
        }

        template<class T>
        constexpr auto set_unique(empty_set<T>)noexcept->empty_set<T> {
            return {};
        }

        template<class T, T V, T ...Vs>
        constexpr auto set_unique(set<T, V, Vs...>)noexcept {
            if constexpr (sizeof...(Vs) == 0)
                return set<T, V>{};
            else {
                return set_union(set<T, V>{}, set_unique(set<T, Vs...>{}));
            }
        }

        template<class T, T V, T ...Vs>
        constexpr T front(set<T, V, Vs...>)noexcept {
            return V;
        }

        template<class T, T V, T ...Vs>
        constexpr T back(set<T, V, Vs...>)noexcept {
            if constexpr (sizeof...(Vs) == 0)
                return V;
            else {
                return back(set<T, Vs...>{});
            }
        }

        template<size_t N, class T, T V, T ...Vs>
        constexpr T get(set<T, V, Vs...>)noexcept {
            if constexpr (N == 0)
                return V;
            else {
                return get<N - 1>(set<T, Vs...>{});
            }
        }

        template<size_t N>
        struct fixed_string {
            char _data[N] = {};
            size_t _size{ 0 };

            constexpr fixed_string()noexcept = default;

            constexpr fixed_string(const char(&str)[N + 1])noexcept {
                for (size_t i = 0; i < N; ++i) {
                    _data[i] = str[i];
                }
                _size = N;
            }

            constexpr fixed_string(const fixed_string& other)noexcept {
                _size = other._size;
                for (size_t i = 0; i < _size; ++i)
                    _data[i] = other._data[i];
            }

            constexpr size_t size()const noexcept {
                return _size;
            }

            constexpr bool empty()const noexcept {
                return _size == 0;
            }

            constexpr const char* data()const noexcept {
                return _data;
            }

            constexpr char operator[](size_t idx)const noexcept {
                return _data[idx];
            }
        };

        template<size_t N>
        fixed_string(const char(&)[N]) -> fixed_string<N - 1>;

        template<size_t N>
        fixed_string(fixed_string<N>) -> fixed_string<N>;

        inline constexpr auto alphabet_set = set<char,
            'x', 'c', 'b', 'B', '?', 'h', 'H', 'i', 'I', 'l', 'L', 'q', 'Q', 'n', 'N', 'e', 'f', 'd', 's', 'p', 'P'
        >{};

        inline constexpr auto digit_set = set<char, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'>{};
        inline constexpr auto start_char_set = set_remove<char, '0'>(digit_set) + alphabet_set + set<char, '!', '=', '@', '<', '>'>{};
        inline constexpr auto not_support_set = set<char, 'f', 'e', 'd'>{};

        template<char C, size_t Count = 1>
        struct term {
            static constexpr char value = C;
            static constexpr size_t count = Count;
        };

        enum struct state_t {
            start,

            parsing_char,
            parsing_zero,
            parsing_integer,

            end
        };

        inline constexpr auto valid_end_set = set<state_t,
            state_t::start,
            state_t::parsing_char,
            state_t::end
        >{};

        template<fixed_string Str, size_t Start = 0, class Stack = empty_list, state_t State = state_t::start>
        constexpr auto __parse()noexcept {
            if constexpr (Start == Str.size()) {
                static_assert(Start != Str.size() || contains<state_t, State>(valid_end_set), "Invalid ending.");
                return Stack{};
            }
            else if constexpr (Str[Start] == ' ') {
                static_assert(Start == Str.size() || Str[Start] != ' ' ||
                    (State != state_t::parsing_zero && State != state_t::parsing_integer), "A count and its format must not contain whitespace.");
                return __parse<Str, Start + 1, Stack, State>();
            }
            else {
                constexpr char c = Str[Start];
                if constexpr (State == state_t::start) {
                    static_assert(Start == Str.size() || State != state_t::start || contains<char, c>(start_char_set), "The first character is invalid.");
                    if constexpr (c == '0') {
                        return __parse<Str, Start + 1, Stack, state_t::parsing_zero>();
                    }
                    else if constexpr (contains<char, c>(set_remove<char, '0'>(digit_set))) {
                        using stack_1 = decltype(push_back(Stack{}, term<' ', c - '0'>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_integer>();
                    }
                    else if constexpr (c == 'P') {
                        using first_term_t = front_t<Stack>;
                        constexpr char first_c = first_term_t::value;
                        static_assert(Start == Str.size() || State != state_t::start || c != 'P' ||
                            first_c == '@' || contains<char, first_c>(alphabet_set) ||
                            contains<char, first_c>(digit_set), "The 'P' format character is only available for the native byte ordering (selected as the default or with the '@' byte order character).");
                        using stack_1 = decltype(push_back(Stack{}, term<'P'>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_char>();
                    }
                    else {
                        static_assert(Start == Str.size() || State != state_t::start || contains<char, c>(digit_set) || !contains<char, c>(not_support_set), "Formats 'e', 'f' and 'd' are not yet supported.");
                        using stack_1 = decltype(push_back(Stack{}, term<c>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_char>();
                    }
                }
                else if constexpr (State == state_t::parsing_char) {
                    static_assert(Start == Str.size() || State != state_t::parsing_char || contains<char, c>(alphabet_set + digit_set), "Invalid character.");
                    if constexpr (c == '0') {
                        return __parse<Str, Start + 1, Stack, state_t::parsing_zero>();
                    }
                    else if constexpr (contains<char, c>(set_remove<char, '0'>(digit_set))) {
                        using stack_1 = decltype(push_back(Stack{}, term<' ', c - '0'>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_integer>();
                    }
                    else if constexpr (c == 'P') {
                        using first_term_t = front_t<Stack>;
                        constexpr char first_c = first_term_t::value;
                        static_assert(Start == Str.size() || State != state_t::parsing_char || c != 'P' ||
                            first_c == '@' || contains<char, first_c>(alphabet_set) ||
                            contains<char, first_c>(digit_set), "The 'P' format character is only available for the native byte ordering (selected as the default or with the '@' byte order character).");
                        using stack_1 = decltype(push_back(Stack{}, term<'P'>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_char>();
                    }
                    else {
                        static_assert(Start == Str.size() || State != state_t::parsing_char || contains<char, c>(digit_set) || !contains<char, c>(not_support_set), "Formats 'e', 'f' and 'd' are not yet supported.");
                        using stack_1 = decltype(push_back(Stack{}, term<c>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_char>();
                    }
                }
                else if constexpr (State == state_t::parsing_zero) {
                    static_assert(Start == Str.size() || State != state_t::parsing_zero || contains<char, c>(alphabet_set), "Invalid character after '0'.");
                    if constexpr (c == 'c' || c == 's') {
                        using stack_1 = decltype(push_back(Stack{}, term<c, 0>{}));
                        return __parse<Str, Start + 1, stack_1, state_t::parsing_char>();
                    }
                    else {
                        return __parse<Str, Start + 1, Stack, state_t::parsing_char>();
                    }
                }
                else if constexpr (State == state_t::parsing_integer) {
                    using top_t = back_t<Stack>;
                    constexpr size_t x = top_t::count;
                    if constexpr (contains<char, c>(digit_set)) {
                        using stack_1 = decltype(pop_back(Stack{}));
                        using stack_2 = decltype(push_back(stack_1{}, term<' ', x * 10 + (c - '0')>{}));
                        return __parse<Str, Start + 1, stack_2, state_t::parsing_integer>();
                    }
                    else if constexpr (c == 'P') {
                        using first_term_t = front_t<Stack>;
                        constexpr char first_c = first_term_t::value;
                        static_assert(Start == Str.size() || State != state_t::parsing_integer || c != 'P' ||
                            first_c == '@' || contains<char, first_c>(alphabet_set) ||
                            contains<char, first_c>(digit_set), "The 'P' format character is only available for the native byte ordering (selected as the default or with the '@' byte order character).");
                        using stack_1 = decltype(pop_back(Stack{}));
                        using stack_2 = decltype(push_back(stack_1{}, term<'P', x>{}));
                        return __parse<Str, Start + 1, stack_2, state_t::parsing_char>();
                    }
                    else {
                        static_assert(Start == Str.size() || State != state_t::parsing_integer || contains<char, c>(digit_set) || contains<char, c>(alphabet_set), "Invalid character after integer.");
                        static_assert(Start == Str.size() || State != state_t::parsing_integer || contains<char, c>(digit_set) || !contains<char, c>(not_support_set), "Formats 'e', 'f' and 'd' are not yet supported.");
                        using stack_1 = decltype(pop_back(Stack{}));
                        using stack_2 = decltype(push_back(stack_1{}, term<c, x>{}));
                        return __parse<Str, Start + 1, stack_2, state_t::parsing_char>();
                    }
                }
                else { // state_t::end
                    return Stack{};
                }
            }
        }

        template<fixed_string Fmt>
        constexpr auto parse()noexcept {
            constexpr auto terms = __parse<Fmt>();
            constexpr size_t len = list_size(terms);
            if constexpr (len == 0)
                return terms;
            else {
                using first_t = front_t<decltype(terms)>;
                constexpr char first_c = first_t::value;
                if constexpr (!contains<char, first_c>(set<char, '<', '>', '@', '!', '='>{})) {
                    return push_front(terms, term<'@'>{});
                }
                else {
                    return terms;
                }
            }
        }

#ifdef _MSC_VER
#if defined(_M_IX86) || defined(_M_X64)
#define __BINARY_LITTLE_ENDIAN__
#else
#define __BINARY_LITTLE_ENDIAN__
#endif
#else
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __BINARY_LITTLE_ENDIAN__
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BINARY_BIG_ENDIAN__
#else
#define __BINARY_LITTLE_ENDIAN__
#endif
#endif

        constexpr bool native_is_big_endian()noexcept {
#if __cplusplus >= 201907L
            return std::endian::native == std::endian::big;
#else
#ifdef __BINARY_LITTLE_ENDIAN__
            return false;
#else
            return true;
#endif
#endif
        }

        template<class T>
        constexpr T byteswap(T x)noexcept {
            constexpr size_t n = sizeof(T);
            static_assert(n == 1 || n == 2 || n == 4 || n == 8 || n == 16, "sizeof(T) must be 1, 2, 4, 8, or 16");
            if constexpr (n == 1)
                return x;
#if __cpp_lib_byteswap
            return std::byteswap(x);
#else
            if constexpr (n == 2) {
#ifdef _WIN32
                return _byteswap_ushort(x);
#else
                return __builtin_bswap16(x);
#endif
            }
            else if constexpr (n == 4) {
#ifdef _WIN32
                return _byteswap_ulong(x);
#else
                return __builtin_bswap32(x);
#endif
            }
            else if constexpr (n == 8) {
#ifdef _WIN32
                return _byteswap_uint64(x);
#else
                return __builtin_bswap64(x);
#endif
            }
            else if constexpr (n == 16) {
#ifdef _WIN32
                return _byteswap_uint128(x);
#else
#if __has_builtin(__builtin_bswap128)
                return __builtin_bswap128(x);
#else
                return (__builtin_bswap64(x >> 64)
                    | (static_cast<T>(__builtin_bswap64(x)) << 64));
#endif
#endif
            }
#endif
        }

        template<class T, size_t Offset, bool IsBigEndian>
        inline T read_bytes(const void* buf)noexcept {
            if constexpr (IsBigEndian == native_is_big_endian()) {
                return *reinterpret_cast<const T*>((const char*)buf + Offset);
            }
            else {
                return byteswap(*reinterpret_cast<const T*>((const char*)buf + Offset));
            }
        }

        template<class T, size_t Offset, bool IsBigEndian>
        inline void write_bytes(void* buf, T x)noexcept {
            if constexpr (IsBigEndian == native_is_big_endian()) {
                *reinterpret_cast<T*>((char*)buf + Offset) = x;
            }
            else {
                *reinterpret_cast<T*>((char*)buf + Offset) = byteswap(x);
            }
        }

        struct empty_operation {};

        template<size_t Offset, size_t Count>
        struct padding_operation {
            static constexpr bool is_padding_operation()noexcept { return true; }

            static void pack(void* buf)noexcept {
                std::memset((char*)buf + Offset, 0, Count);
            }
        };

        template<class Op>
        concept is_padding_operation = requires(Op) {
            Op::is_padding_operation();
        };

        template<class Op>
        concept is_pascal_string_op = requires(Op) {
            Op::is_pascal_string();
        };

        template<char C, size_t Offset, size_t Count, bool IsBig>
        struct read_operation {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                std::terminate();
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'c', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, char>, "Can not be assigned by a char.");
                if constexpr (Count == 0)
                    x = '\0';
                else
                    x = *((const char*)buf + Offset);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'b', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, signed char>, "Can not be assigned by a signed char.");
                x = *((const signed char*)buf + Offset);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'B', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, unsigned char>, "Can not be assigned by a unsigned char.");
                x = *((const unsigned char*)buf + Offset);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'?', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, bool>, "Can not be assigned by a bool.");
                x = *((const unsigned char*)buf + Offset) != 0;
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'h', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, short>, "Can not be assigned by a short.");
                x = read_bytes<short, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'H', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, unsigned short>, "Can not be assigned by a unsigned short.");
                x = read_bytes<unsigned short, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'i', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, int>, "Can not be assigned by an int.");
                x = read_bytes<int, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'I', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, unsigned int>, "Can not be assigned by a unsigned int.");
                x = read_bytes<unsigned int, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'l', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, long>, "Can not be assigned by a long.");
                x = read_bytes<long, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'L', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, unsigned long>, "Can not be assigned by a unsigned long.");
                x = read_bytes<unsigned long, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'q', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, long long>, "Can not be assigned by a long long.");
                x = read_bytes<long long, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'Q', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, unsigned long long>, "Can not be assigned by a unsigned long long.");
                x = read_bytes<unsigned long long, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'n', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, __ssize_t>, "Can not be assigned by a ssize_t.");
                x = read_bytes<__ssize_t, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'N', Offset, Count, IsBig> {
            template<class T>
            static void unpack(const void* buf, T& x)noexcept {
                static_assert(std::is_nothrow_assignable_v<T&, size_t>, "Can not be assigned by a size_t.");
                x = read_bytes<size_t, Offset, IsBig>(buf);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'e', Offset, Count, IsBig> {
            //TODO
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'f', Offset, Count, IsBig> {
            //TODO
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'d', Offset, Count, IsBig> {
            //TODO
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'s', Offset, Count, IsBig> {
            static void unpack(const void* buf, std::string& x)noexcept {
                x.resize(Count);
                if constexpr (Count > 0)
                    std::memcpy(x.data(), (const char*)buf + Offset, Count);
            }

            template<size_t N>
                requires (N >= Count && N > 0)
            static void unpack(const void* buf, char(&x)[N])noexcept {
                if constexpr (Count > 0)
                    std::memcpy(x, (const char*)buf + Offset, Count);
                if constexpr (N > Count)
                    x[Count] = '\0';
            }

            template<class T>
                requires std::is_nothrow_assignable_v<T&, std::string_view>
            static void unpack(const void* buf, T& x)noexcept {
                x = std::string_view{ (const char*)buf + Offset, Count };
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'p', Offset, Count, IsBig> {
            static constexpr bool is_pascal_string()noexcept { return true; }
            // TODO
            static size_t unpack(const void* buf, size_t size, std::error_code& ec, std::string& str)noexcept {
                const size_t len = *((const char*)buf + Offset);
                if (Offset + len > size) {
                    ec = std::error_code((int)binary_error::out_of_range, binary_category);
                    return 0;
                }
                str.resize(len - 1);
                std::memcpy(str.data(), (const char*)buf + Offset + 1, len - 1);
                return len;
            }

            template<size_t N>
                requires (N >= 254)
            static size_t unpack(const void* buf, size_t size, std::error_code& ec, char(&x)[N])noexcept {
                const size_t len = *((const char*)buf + Offset);
                if (Offset + len > size) {
                    ec = std::error_code((int)binary_error::out_of_range, binary_category);
                    return 0;
                }
                std::memcpy(x, (const char*)buf + Offset + 1, len - 1);
                if (N > len - 1)
                    x[len - 1] = '\0';
                return len;
            }

            template<class View>
                requires std::is_nothrow_assignable_v<View&, std::string_view>
            static size_t unpack(const void* buf, size_t size, std::error_code& ec, View& x)noexcept {
                const size_t len = *((const char*)buf + Offset);
                if (Offset + len > size) {
                    ec = std::error_code((int)binary_error::out_of_range, binary_category);
                    return 0;
                }
                x = std::string_view((const char*)buf + Offset + 1, len - 1);
                return len;
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct read_operation<'P', Offset, Count, IsBig> {
            static void unpack(const void* buf, void*& x)noexcept {
                x = (void*)read_bytes<intptr_t, Offset, native_is_big_endian()>(buf);
            }
        };

        //

        template<char C, size_t Offset, size_t Count, bool IsBig>
        struct write_operation {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                std::terminate();
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'c', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, char>, "Can not convert to a char.");
                if constexpr (Count == 0)
                    write_bytes<char, Offset, IsBig>(buf, '\0');
                else
                    write_bytes<char, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'b', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, signed char>, "Can not convert to a signed char.");
                write_bytes<signed char, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'B', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, unsigned char>, "Can not convert to a unsigned char.");
                write_bytes<unsigned char, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'?', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, bool>, "Can not convert to a bool.");
                const bool flag = x;
                write_bytes<uint8_t, Offset, IsBig>(buf, flag ? 1 : 0);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'h', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, short>, "Can not convert to a short.");
                write_bytes<short, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'H', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, unsigned short>, "Can not convert to a unsigned short.");
                write_bytes<unsigned short, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'i', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, int>, "Can not convert to an int.");
                write_bytes<int, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'I', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, unsigned int>, "Can not convert to a unsigned int.");
                write_bytes<unsigned int, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'l', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, long>, "Can not convert to a long.");
                write_bytes<long, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'L', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, unsigned long>, "Can not convert to a unsigned long.");
                write_bytes<unsigned long, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'q', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, long long>, "Can not convert to a long long.");
                write_bytes<long long, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'Q', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, unsigned long long>, "Can not convert to a unsigned long long.");
                write_bytes<unsigned long long, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'n', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, __ssize_t>, "Can not convert to a ssize_t.");
                write_bytes<__ssize_t, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'N', Offset, Count, IsBig> {
            template<class T>
            static void pack(void* buf, const T& x)noexcept {
                static_assert(std::is_nothrow_convertible_v<const T&, size_t>, "Can not convert to a size_t.");
                write_bytes<size_t, Offset, IsBig>(buf, x);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'e', Offset, Count, IsBig> {
            //TODO
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'f', Offset, Count, IsBig> {
            //TODO
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'d', Offset, Count, IsBig> {
            //TODO
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'s', Offset, Count, IsBig> {
            static void pack(void* buf, const std::string_view& x)noexcept {
                if constexpr (Count > 0) {
                    if (Count <= x.size()) {
                        std::memcpy((char*)buf + Offset, x.data(), Count);
                    }
                    else {
                        std::memcpy((char*)buf + Offset, x.data(), x.size());
                        std::memset((char*)buf + Offset + x.size(), 0, Count - x.size());
                    }
                }
            }

            template<size_t N>
            static void pack(void* buf, const char(&x)[N])noexcept {
                if constexpr (Count > 0) {
                    std::memcpy((char*)buf + Offset, x, Count < N ? Count : N);
                    if constexpr (N < Count) {
                        std::memset((char*)buf + Offset + N, 0, Count - N);
                    }
                }
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'p', Offset, Count, IsBig> {
            static constexpr bool is_pascal_string()noexcept { return true; }
            // TODO
            static size_t pack(void* buf, size_t size, std::error_code& ec, const std::string_view& str)noexcept {
                const size_t len = str.size() < 254 ? str.size() : 254;
                if (Offset + 1 + len > size) {
                    ec = std::error_code((int)binary_error::out_of_range, binary_category);
                    return 0;
                }
                std::memcpy((char*)buf + Offset + 1, str.data(), len);
                write_bytes<uint8_t, Offset, IsBig>(buf, (uint8_t)(len + 1));
                return len + 1;
            }

            template<size_t N>
            static size_t pack(void* buf, size_t size, std::error_code& ec, char(&x)[N])noexcept {
                const std::string_view str{ x };
                return pack(buf, size, ec, str);
            }
        };

        template<size_t Offset, size_t Count, bool IsBig>
        struct write_operation<'P', Offset, Count, IsBig> {
            static void pack(void* buf, const void* x)noexcept {
                write_bytes<intptr_t, Offset, IsBig>(buf, (intptr_t)x);
            }
        };

        constexpr bool fmt_is_big(empty_list)noexcept { return native_is_big_endian(); }

        template<class Terms>
        constexpr bool fmt_is_big(Terms)noexcept {
            using first_term = front_t<Terms>;
            constexpr char c = first_term::value;
            if constexpr (c == '@' || c == '=')
                return native_is_big_endian();
            if constexpr (c == '<')
                return false;
            return true;
        }

        constexpr bool fmt_is_standard_size(empty_list)noexcept { return false; }

        template<class Terms>
        constexpr bool fmt_is_standard_size(Terms)noexcept {
            using first_term_t = front_t<Terms>;
            constexpr char c = first_term_t::value;
            return c != '@';
        }

        template<class Term, bool IsStandardSize>
        constexpr size_t get_term_size()noexcept {
            constexpr char c = Term::value;
            constexpr size_t count = Term::count;
            if constexpr (c == 'c') {
                if constexpr (count == 0)
                    return IsStandardSize ? 1 : sizeof(char);
                return (IsStandardSize ? 1 : sizeof(char)) * count;
            }
            else if constexpr (c == 'b' || c == 'B' || c == '?') {
                return (IsStandardSize ? 1 : sizeof(char)) * count;
            }
            else if constexpr (c == 'h' || c == 'H' || c == 'e') {
                return (IsStandardSize ? 2 : sizeof(short)) * count;
            }
            else if constexpr (c == 'i' || c == 'I' || c == 'l' || c == 'L' || c == 'f') {
                return (IsStandardSize ? 4 : sizeof(int)) * count;
            }
            else if constexpr (c == 'q' || c == 'Q' || c == 'd') {
                return (IsStandardSize ? 8 : sizeof(long long)) * count;
            }
            else if constexpr (c == 'n' || c == 'N') {
                return sizeof(size_t) * count;
            }
            else if constexpr (c == 'P') {
                return sizeof(void*) * count;
            }
            else if constexpr (c == 's') {
                return (IsStandardSize ? 1 : sizeof(char)) * count;
            }
            else if constexpr (c == 'p') {
                return 0;
            }
            else { // c == 'x'
                return count;
            }
        }

        template<size_t Start, bool IsStandardSize>
        constexpr size_t get_offset(empty_list)noexcept {
            return 0;
        }

        template<size_t Start, bool IsStandardSize, class Term, class ...Terms>
        constexpr size_t get_offset(list<Term, Terms...>)noexcept {
            if constexpr (Start == 0) {
                return 0;
            }
            else {
                return get_term_size<Term, IsStandardSize>() + get_offset<Start - 1, IsStandardSize>(list<Terms...>{});
            }
        }

        constexpr size_t index_of_first_pascal_string_op(empty_list)noexcept { return 0; }

        template<class Op, class ...Ops>
        constexpr size_t index_of_first_pascal_string_op(list<Op, Ops...>)noexcept {
            if constexpr (is_pascal_string_op<Op>)
                return 0;
            else {
                return 1 + index_of_first_pascal_string_op(list<Ops...>{});
            }
        }

        constexpr auto flat_terms(empty_list)noexcept->empty_list { return {}; }

        template<class Term, class ...Terms>
        constexpr auto flat_terms(list<Term, Terms...>)noexcept {
            if constexpr (sizeof...(Terms) == 0) {
                constexpr char c = Term::value;
                constexpr size_t count = Term::count;
                if constexpr (count <= 1) {
                    return list<Term>{};
                }
                else if constexpr (c == 's' || c == 'x') {
                    return list<Term>{};
                }
                else {
                    return[]<size_t ...Idx>(std::index_sequence<Idx...>)constexpr {
                        constexpr char c = Term::value;
                        return (
                            empty_list{} + ... + list<term<c, (Idx, 1)>>{}
                        );
                    }(std::make_index_sequence<count>{});
                }
            }
            else {
                return (
                    flat_terms(list<Term>{}) + ... +
                    []()constexpr {
                        constexpr char c = Terms::value;
                        constexpr size_t count = Terms::count;
                        if constexpr (count <= 1) {
                            return list<term<c, count>>{};
                        }
                        else if constexpr (c == 's' || c == 'x') {
                            return list<term<c, count>>{};
                        }
                        else {
                            return[]<size_t ...Idx>(std::index_sequence<Idx...>)constexpr {
                                constexpr char c = Terms::value;
                                return (
                                    empty_list{} + ... + list<term<c, (Idx, 1)>>{}
                                );
                            }(std::make_index_sequence<count>{});
                        }
                    }()
                        );
            }
        }

        constexpr auto remove_empty_operations(empty_list)noexcept->empty_list {
            return {};
        }

        template<class Op, class ...Ops>
        constexpr auto remove_empty_operations(list<Op, Ops...>)noexcept {
            if constexpr (std::is_same_v<std::decay_t<Op>, empty_operation> || is_padding_operation<std::decay_t<Op>>)
                return remove_empty_operations(list<Ops...>{});
            else
                return list<Op>{} + remove_empty_operations(list<Ops...>{});
        }

        constexpr auto connect_padding(empty_list)noexcept->empty_list { return {}; }

        template<class Term, class ...Terms>
        constexpr auto connect_padding(list<Term, Terms...>)noexcept {
            constexpr size_t first_idx = find_first_of(list<Term, Terms...>{}, [](auto term)constexpr {
                using term_t = decltype(term);
                constexpr char c = term_t::value;
                return c == 'x';
                });
            if constexpr (first_idx == sizeof...(Terms) + 1)
                return list<Term, Terms...>{};
            else {
                constexpr size_t end_idx = find_first_of(range<first_idx, sizeof...(Terms) + 1>(list<Term, Terms...>{}), [](auto term)constexpr {
                    using term_t = decltype(term);
                    constexpr char c = term_t::value;
                    return c != 'x';
                    }) + first_idx;
                using list_t = list<Term, Terms...>;
                constexpr size_t total_padding = []<size_t ...Idx>(std::index_sequence<Idx...>)constexpr {
                    return (
                        0 + ... + get<first_idx + Idx>(list_t{}).count
                        );
                }(std::make_index_sequence<end_idx - first_idx>{});
                using connected_terms_t = decltype(replace_with<first_idx, end_idx>(list<Term, Terms...>{}, list<term<'x', total_padding>>{}));
                constexpr size_t connected_size = list_size(connected_terms_t{});
                if constexpr (connected_size == first_idx + 1)
                    return connected_terms_t{};
                else
                    return range<0, first_idx + 1>(connected_terms_t{}) + connect_padding(range<first_idx + 1, connected_size>(connected_terms_t{}));
            }
        }

        template<fixed_string Fmt>
        struct unpack_t {
        private:
            static constexpr auto _terms = flat_terms(parse<Fmt>());
            static constexpr bool _is_big = fmt_is_big(_terms);
            static constexpr bool _is_standard_size = fmt_is_standard_size(_terms);

            template<class ...Terms>
            static constexpr auto __get_operations(list<Terms...>)noexcept {
                using list_t = list<Terms...>;
                return[]<size_t ...Idx>(std::index_sequence<Idx...>)constexpr {
                    return (
                        empty_list{} + ... +
                        []()constexpr {
                            using term_t = decltype(get<Idx>(list<Terms...>{}));
                            constexpr char c = term_t::value;
                            constexpr size_t count = term_t::count;
                            constexpr size_t offset = get_offset<Idx, _is_standard_size>(list_t{});
                            if constexpr (c == 'x')
                                return list<empty_operation>{};
                            else
                                return list<read_operation<c, offset, count, _is_big>>{};
                        }()
                            );
                }(std::make_index_sequence<sizeof...(Terms)>{});
            }

            template<class Terms, class ...Args>
            static size_t __unpack(const void* buf, size_t size, std::error_code& ec, Args& ...args)noexcept {
                using operations_t = decltype(__get_operations(Terms{}));
                static_assert(list_size(operations_t{}) == list_size(Terms{}));
                static_assert(list_size(remove_empty_operations(operations_t{})) == sizeof...(Args), "The number of arguments does not match the format string.");
                constexpr size_t total_size = get_offset < list_size(Terms{}), _is_standard_size > (Terms{});
                if constexpr (sizeof...(Args) > 0) {
                    if (size < total_size) {
                        ec = std::error_code{(int)binary_error::out_of_range, binary_category};
                        return 0;
                    }
                    auto args_tuple = std::tie(args...);
                    constexpr size_t pascal_op_idx = index_of_first_pascal_string_op(operations_t{});
                    [buf, &args_tuple] <size_t ...Idx>(std::index_sequence<Idx...>)noexcept {
                        (
                            [buf, &args_tuple]()noexcept {
                                using op_t = decltype(get<Idx>(operations_t{}));
                                constexpr size_t arg_idx = list_size(remove_empty_operations(range<0, Idx>(operations_t{})));
                                if constexpr (!std::is_same_v<std::decay_t<op_t>, empty_operation>) {
                                    op_t::unpack(buf, std::get<arg_idx>(args_tuple));
                                }
                            }(), ...
                                );
                    }(std::make_index_sequence<pascal_op_idx>{});
                    constexpr size_t pascal_string_arg_idx = list_size(remove_empty_operations(range<0, pascal_op_idx>(operations_t{})));
                    if constexpr (pascal_string_arg_idx < sizeof...(Args)) {
                        using op_t = decltype(get<pascal_op_idx>(operations_t{}));
                        const size_t pascal_string_len = op_t::unpack(buf, size, ec, std::get<pascal_string_arg_idx>(args_tuple));
                        if (pascal_string_len == 0) {
                            return 0;
                        }
                        const size_t parsed_size = get_offset<pascal_op_idx, _is_standard_size>(Terms{}) + pascal_string_len;
                        if constexpr (pascal_string_arg_idx + 1 < sizeof...(Args)) {
                            auto sub_args_tuple = [pascal_string_arg_idx, &args_tuple]<size_t ...Idx>(std::index_sequence<Idx...>)noexcept {
                                return std::tie(std::get<pascal_string_arg_idx + 1 + Idx>(args_tuple)...);
                            }(std::make_index_sequence<sizeof...(Args) - pascal_string_arg_idx - 1>{});
                            return parsed_size + std::apply([&](auto& ...args1)noexcept {
                                constexpr auto sub_terms = range < pascal_op_idx + 1, list_size(Terms{}) > (Terms{});
                                using sub_terms_t = decltype(sub_terms);
                                return __unpack<sub_terms_t>((const char*)buf + parsed_size, size - parsed_size, ec, args1...);
                                }, sub_args_tuple);
                        }
                        return parsed_size;
                    }
                    else {
                        // No pascal string
                        return total_size;
                    }
                }
                return 0;
            }
        public:
            template<class ...Args>
            size_t operator()(const void* buf, size_t size, Args& ...args)const {
                if constexpr (list_size(_terms) > 1) {
                    std::error_code ec;
                    const size_t parsed_size = __unpack<decltype(pop_front(_terms))>(buf, size, ec, args...);
                    if (ec)
                        throw std::system_error{ ec };
                    return parsed_size;
                }
                return 0;
            }

            template<class ...Args>
            size_t operator()(const void* buf, size_t size, std::error_code& ec, Args& ...args)const {
                if constexpr (list_size(_terms) > 1) {
                    return __unpack<decltype(pop_front(_terms))>(buf, size, ec, args...);
                }
                return 0;
            }
        };

        template<fixed_string Fmt>
        struct pack_t {
        private:
            static constexpr auto _terms = flat_terms(connect_padding(parse<Fmt>()));
            static constexpr bool _is_big = fmt_is_big(_terms);
            static constexpr bool _is_standard_size = fmt_is_standard_size(_terms);

            template<class ...Terms>
            static constexpr auto __get_operations(list<Terms...>)noexcept {
                using list_t = list<Terms...>;
                return[]<size_t ...Idx>(std::index_sequence<Idx...>)constexpr {
                    return (
                        empty_list{} + ... +
                        []()constexpr {
                            using term_t = decltype(get<Idx>(list_t{}));
                            constexpr char c = term_t::value;
                            constexpr size_t count = term_t::count;
                            constexpr size_t offset = get_offset<Idx, _is_standard_size>(list_t{});
                            if constexpr (c == 'x')
                                return list<padding_operation<offset, count>>{};
                            else
                                return list<write_operation<c, offset, count, _is_big>>{};
                        }()
                            );
                }(std::make_index_sequence<sizeof...(Terms)>{});
            }

            template<class Terms, class ...Args>
            static size_t __pack(void* buf, const size_t size, std::error_code& ec, const Args& ...args)noexcept {
                using operations_t = decltype(__get_operations(Terms{}));
                static_assert(list_size(operations_t{}) == list_size(Terms{}));
                static_assert(list_size(remove_empty_operations(operations_t{})) == sizeof...(Args), "The number of arguments does not match the format string.");
                constexpr size_t total_size = get_offset < list_size(Terms{}), _is_standard_size > (Terms{});
                if constexpr (sizeof...(Args) > 0) {
                    if (size < total_size) {
                        ec = std::error_code{ (int)binary_error::out_of_range, binary_category };
                        return 0;
                    }
                    const auto& args_tuple = std::tie(args...);
                    constexpr size_t pascal_op_idx = index_of_first_pascal_string_op(operations_t{});
                    [buf, &args_tuple] <size_t ...Idx>(std::index_sequence<Idx...>)noexcept {
                        (
                            [buf, &args_tuple]()noexcept {
                                using op_t = decltype(get<Idx>(operations_t{}));
                                constexpr size_t arg_idx = list_size(remove_empty_operations(range<0, Idx>(operations_t{})));
                                if constexpr (is_padding_operation<op_t>)
                                    op_t::pack(buf);
                                else
                                    op_t::pack(buf, std::get<arg_idx>(args_tuple));
                            }(), ...
                                );
                    }(std::make_index_sequence<pascal_op_idx>{});
                    constexpr size_t pascal_string_arg_idx = list_size(remove_empty_operations(range<0, pascal_op_idx>(operations_t{})));
                    if constexpr (pascal_string_arg_idx < sizeof...(Args)) {
                        using op_t = decltype(get<pascal_op_idx>(operations_t{}));
                        const size_t pascal_string_len = op_t::pack(buf, size, ec, std::get<pascal_string_arg_idx>(args_tuple));
                        if (pascal_string_len == 0) {
                            return 0;
                        }
                        const size_t packed_size = get_offset<pascal_op_idx, _is_standard_size>(Terms{}) + pascal_string_len;
                        if constexpr (pascal_string_arg_idx + 1 < sizeof...(Args)) {
                            const auto& sub_args_tuple = [pascal_string_arg_idx, &args_tuple]<size_t ...Idx>(std::index_sequence<Idx...>)noexcept {
                                return std::tie(std::get<pascal_string_arg_idx + 1 + Idx>(args_tuple)...);
                            }(std::make_index_sequence<sizeof...(Args) - pascal_string_arg_idx - 1>{});
                            return packed_size + std::apply([&](const auto& ...args1)noexcept {
                                constexpr auto sub_terms = range < pascal_op_idx + 1, list_size(Terms{}) > (Terms{});
                                using sub_terms_t = decltype(sub_terms);
                                return __pack<sub_terms_t>((char*)buf + packed_size, size - packed_size, ec, args1...);
                                }, sub_args_tuple);
                        }
                        return packed_size;
                    }
                    else {
                        // No pascal string
                        return total_size;
                    }
                }
                return 0;
            }
        public:
            template<class ...Args>
            size_t operator()(void* buf, size_t size, const Args& ...args)const {
                if constexpr (list_size(_terms) > 1) {
                    std::error_code ec;
                    const size_t packed_size = __pack<decltype(pop_front(_terms))>(buf, size, ec, args...);
                    if (ec)
                        throw std::system_error{ ec };
                    return packed_size;
                }
                return 0;
            }

            template<class ...Args>
            size_t operator()(void* buf, size_t size, std::error_code& ec, const Args& ...args)const {
                if constexpr (list_size(_terms) > 1) {
                    return __pack<decltype(pop_front(_terms))>(buf, size, ec, args...);
                }
                return 0;
            }
        };
    } // __detail

    using __detail::fixed_string;
    using __detail::byteswap;
    using __detail::native_is_big_endian;
    using __detail::binary_error;
    using __detail::binary_category;

    template<fixed_string Fmt>
    inline constexpr __detail::unpack_t<Fmt> unpack{};

    template<fixed_string Fmt>
    inline constexpr __detail::pack_t<Fmt> pack{};

    template<std::integral T>
    constexpr T read_big(const void* buf)noexcept {
        return __detail::read_bytes<T, 0, true>(buf);
    }

    template<std::integral T>
    constexpr T read_little(const void* buf)noexcept {
        return __detail::read_bytes<T, 0, false>(buf);
    }

    template<std::integral T>
    constexpr void write_big(void* buf, typename std::remove_reference<T>::type value)noexcept {
        __detail::write_bytes<T, 0, true>(buf, value);
    }

    template<std::integral T>
    constexpr void write_little(void* buf, typename std::remove_reference<T>::type value)noexcept {
        __detail::write_bytes<T, 0, false>(buf, value);
    }

    template<std::integral T>
    constexpr auto ntoh(typename std::remove_reference<T>::type value)noexcept {
        if constexpr (native_is_big_endian())
            return value;
        else
            return byteswap(value);
    }

    template<std::integral T>
    constexpr auto hton(typename std::remove_reference<T>::type value)noexcept {
        if constexpr (native_is_big_endian())
            return value;
        else
            return byteswap(value);
    }

} // namespace binary

namespace std {
    template<>
    struct is_error_code_enum<binary::binary_error> : std::true_type {};
}