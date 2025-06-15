// Copyright Ruslan Arutyunyan, 2019-2021.
// Copyright Antony Polukhin, 2021-2023.
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

// Contributed by Ruslan Arutyunyan

#pragma once

#include <memory>
#include <type_traits>
#include <utility>

namespace ice {

template <std::size_t OptimizeForSize, std::size_t OptimizeForAlignment>
class basic_any {
    static_assert(OptimizeForSize > 0 && OptimizeForAlignment > 0,
                  "Size and Align shall be positive values");
    static_assert(OptimizeForSize >= OptimizeForAlignment,
                  "Size shall non less than Align");
    static_assert((OptimizeForAlignment & (OptimizeForAlignment - 1)) == 0,
                  "Align shall be a power of 2");
    static_assert(OptimizeForSize % OptimizeForAlignment == 0,
                  "Size shall be multiple of alignment");

  private:
    /// @cond
    enum operation { Destroy, Move, UnsafeCast };

    template <typename ValueType>
    static void *small_manager(operation op, basic_any &left,
                               const basic_any *right) {
        switch (op) {
        case Destroy:
            reinterpret_cast<ValueType *>(&left.content.small_value)
                ->~ValueType();
            break;
        case Move: {
            ValueType *value = reinterpret_cast<ValueType *>(
                &const_cast<basic_any *>(right)->content.small_value);
            new (&left.content.small_value) ValueType(std::move(*value));
            left.man = right->man;
            reinterpret_cast<ValueType const *>(&right->content.small_value)
                ->~ValueType();
            const_cast<basic_any *>(right)->man = 0;
        }; break;
        case UnsafeCast:
            return reinterpret_cast<typename std::remove_cv<ValueType>::type *>(
                &left.content.small_value);
        }
        return 0;
    }

    template <typename ValueType>
    static void *large_manager(operation op, basic_any &left,
                               const basic_any *right) {
        switch (op) {
        case Destroy:
            delete static_cast<ValueType *>(left.content.large_value);
            break;
        case Move:
            left.content.large_value = right->content.large_value;
            left.man = right->man;
            const_cast<basic_any *>(right)->content.large_value = 0;
            const_cast<basic_any *>(right)->man = 0;
            break;
        case UnsafeCast:
            return reinterpret_cast<typename std::remove_cv<ValueType>::type *>(
                left.content.large_value);
        }
        return 0;
    }

    template <typename ValueType>
    struct is_small_object
        : std::integral_constant<
              bool, sizeof(ValueType) <= OptimizeForSize &&
                        alignof(ValueType) <= OptimizeForAlignment &&
                        std::is_nothrow_move_constructible<ValueType>::value> {
    };

    template <typename ValueType>
    static void create(basic_any &any, ValueType &&value, std::true_type) {
        typedef typename std::decay<const ValueType>::type DecayedType;
        any.man = &small_manager<DecayedType>;
        new (&any.content.small_value)
            DecayedType(std::forward<ValueType>(value));
    }

    template <typename ValueType>
    static void create(basic_any &any, ValueType &&value, std::false_type) {
        typedef typename std::decay<const ValueType>::type DecayedType;
        any.man = &large_manager<DecayedType>;
        any.content.large_value =
            new DecayedType(std::forward<ValueType>(value));
    }
    /// @endcond

  public: // non-type template parameters accessors
    static constexpr std::size_t buffer_size = OptimizeForSize;
    static constexpr std::size_t buffer_align = OptimizeForAlignment;

  public: // structors
    /// \post this->empty() is true.
    constexpr basic_any() noexcept : man(0), content() {}

    basic_any(basic_any &&other) noexcept : man(0), content() {
        if (other.man) {
            other.man(Move, *this, &other);
        }
    }

    template <typename ValueType>
    basic_any(ValueType &&value,
              typename std::enable_if<
                  !std::is_same<basic_any &, ValueType>::value>::type * =
                  0 // disable if value has type `basic_any&`
              ,
              typename std::enable_if<!std::is_const<ValueType>::value>::type
                  * = 0) // disable if value has type `const ValueType&&`
        : man(0), content() {
        typedef typename std::decay<ValueType>::type DecayedType;
        static_assert(!std::is_same<DecayedType, basic_any>::value,
                      "basic_any shall not be constructed from basic_any");
        create(*this, static_cast<ValueType &&>(value),
               is_small_object<DecayedType>());
    }

    ~basic_any() noexcept {
        if (man) {
            man(Destroy, *this, 0);
        }
    }

  public: // modifiers
    basic_any &swap(basic_any &rhs) noexcept {
        if (this == &rhs) {
            return *this;
        }

        if (man && rhs.man) {
            basic_any tmp;
            rhs.man(Move, tmp, &rhs);
            man(Move, rhs, this);
            tmp.man(Move, *this, &tmp);
        } else if (man) {
            man(Move, rhs, this);
        } else if (rhs.man) {
            rhs.man(Move, *this, &rhs);
        }
        return *this;
    }

    basic_any &operator=(basic_any &&rhs) noexcept {
        rhs.swap(*this);
        basic_any().swap(rhs);
        return *this;
    }

    template <class ValueType> basic_any &operator=(ValueType &&rhs) {
        typedef typename std::decay<ValueType>::type DecayedType;
        static_assert(!std::is_same<DecayedType, basic_any>::value,
                      "basic_any shall not be assigned into basic_any");
        basic_any(std::forward<ValueType>(rhs)).swap(*this);
        return *this;
    }

  public: // queries
    bool empty() const noexcept { return !man; }

    /// \post this->empty() is true
    void clear() noexcept { basic_any().swap(*this); }

  private: // representation
    template <typename ValueType, std::size_t Size, std::size_t Alignment>
    friend ValueType *unsafe_any_cast(basic_any<Size, Alignment> *) noexcept;

    typedef void *(*manager)(operation op, basic_any &left,
                             const basic_any *right);

    manager man;

    union content {
        void *large_value;
        alignas(
            OptimizeForAlignment) unsigned char small_value[OptimizeForSize];
    } content;
    /// @endcond
};

/// Exchange of the contents of `lhs` and `rhs`.
/// \throws Nothing.
template <std::size_t OptimizeForSize, std::size_t OptimizeForAlignment>
inline void
swap(basic_any<OptimizeForSize, OptimizeForAlignment> &lhs,
     basic_any<OptimizeForSize, OptimizeForAlignment> &rhs) noexcept {
    lhs.swap(rhs);
}

template <typename ValueType, std::size_t OptimizedForSize,
          std::size_t OptimizeForAlignment>
inline ValueType *unsafe_any_cast(
    basic_any<OptimizedForSize, OptimizeForAlignment> *operand) noexcept {
    return static_cast<ValueType *>(operand->man(
        basic_any<OptimizedForSize, OptimizeForAlignment>::UnsafeCast, *operand,
        0));
}

template <typename ValueType, std::size_t OptimizeForSize,
          std::size_t OptimizeForAlignment>
inline const ValueType *unsafe_any_cast(
    const basic_any<OptimizeForSize, OptimizeForAlignment> *operand) noexcept {
    return unsafe_any_cast<ValueType>(
        const_cast<basic_any<OptimizeForSize, OptimizeForAlignment> *>(
            operand));
}

} // namespace ice