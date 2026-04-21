#include <cstdint>
#include <stdexcept>
#include <type_traits>

template <std::uint32_t SERIAL_BITS>
class Rfc1982Sequence {
    static_assert(SERIAL_BITS > 0, "SERIAL_BITS must be > 0");

    static constexpr std::uint64_t MODULUS = std::uint64_t(1) << SERIAL_BITS;
    static constexpr std::uint64_t HALF = std::uint64_t(1) << (SERIAL_BITS - 1);
    static constexpr std::uint64_t ADD_MAX = HALF - 1;

    static_assert(ADD_MAX > 0, "SERIAL_BITS must be >= 2 for meaningful add range");

    // 内部存储至少要能放下 0 .. MODULUS-1
    using ValueType = std::uint64_t;

    ValueType value_;

public:
    // 构造（默认为 0）
    explicit constexpr Rfc1982Sequence(ValueType v = 0) noexcept
        : value_(v % MODULUS) {}

    // 获取原始值（在 0 .. MODULUS-1 范围内）
    constexpr ValueType value() const noexcept { return value_; }

    // --- 加法（RFC 1982 第 3.1 节） -----------------------------------------
    Rfc1982Sequence& add(std::uint64_t n) {
        if (n > ADD_MAX) {
            throw std::out_of_range("RFC1982: addition n must be in [0, 2^(SERIAL_BITS-1)-1]");
        }
        value_ = static_cast<ValueType>((value_ + n) % MODULUS);
        return *this;
    }

    // 返回新序列（不修改 this）
    constexpr Rfc1982Sequence plus(std::uint64_t n) const {
        if (n > ADD_MAX) {
            throw std::out_of_range("RFC1982: addition n must be in [0, 2^(SERIAL_BITS-1)-1]");
        }
        return Rfc1982Sequence(static_cast<ValueType>((value_ + n) % MODULUS));
    }

    // 运算符重载（可读性）
    Rfc1982Sequence& operator+=(std::uint64_t n) { return add(n); }

    friend Rfc1982Sequence operator+(Rfc1982Sequence a, std::uint64_t n) {
        return a.plus(n);
    }

    // --- 比较（RFC 1982 第 3.2 节） -----------------------------------------

    // “三态比较结果”，用于处理“未定义比较”的情形
    enum class CompareResult { Less, Equal, Greater, Undefined };

    // 核心比较逻辑，返回三态结果
    constexpr CompareResult compare(const Rfc1982Sequence& other) const noexcept {
        if (value_ == other.value_) return CompareResult::Equal;

        // 使用无界非负整数语义（C++ 本身就是无界语义）
        // 为简化，这里假设 ValueType 足够大，否则用 __int128/大整数扩展
        std::uint64_t i1 = value_;
        std::uint64_t i2 = other.value_;

        if (i1 < i2) {
            std::uint64_t d = i2 - i1;
            if (d < HALF) return CompareResult::Less;
            else if (d > HALF) return CompareResult::Greater;
            else return CompareResult::Undefined; // d == HALF
        } else {
            std::uint64_t d = i1 - i2;
            if (d > HALF) return CompareResult::Less;
            else if (d < HALF) return CompareResult::Greater;
            else return CompareResult::Undefined; // d == HALF
        }
    }

    // 严格弱序风格：对“未定义”情况抛异常，以避免静默产生不一致结果
    static void throwIfUndefined(CompareResult r) {
        if (r == CompareResult::Undefined) {
            throw std::domain_error("RFC1982: comparison is undefined for this pair of sequence numbers");
        }
    }

    // == / !=
    constexpr bool operator==(const Rfc1982Sequence& other) const noexcept {
        return compare(other) == CompareResult::Equal;
    }
    constexpr bool operator!=(const Rfc1982Sequence& other) const noexcept {
        return compare(other) != CompareResult::Equal;
    }

    // < / > / <= / >= （遇到“未定义”抛异常）
    bool operator<(const Rfc1982Sequence& other) const {
        CompareResult r = compare(other);
        throwIfUndefined(r);
        return r == CompareResult::Less;
    }
    bool operator>(const Rfc1982Sequence& other) const {
        CompareResult r = compare(other);
        throwIfUndefined(r);
        return r == CompareResult::Greater;
    }
    bool operator<=(const Rfc1982Sequence& other) const {
        CompareResult r = compare(other);
        throwIfUndefined(r);
        return r != CompareResult::Greater; // Less 或 Equal
    }
    bool operator>=(const Rfc1982Sequence& other) const {
        CompareResult r = compare(other);
        throwIfUndefined(r);
        return r != CompareResult::Less; // Greater 或 Equal
    }
};

// 常用别名：DNS SOA 使用的 32 位序列号
using Rfc1982Sequence32 = Rfc1982Sequence<32>;
