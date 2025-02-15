#pragma once

template <class T, T *T::*Next> struct const_list_iterator {
  using difference_type = std::ptrdiff_t;
  using value_type = T;
  using reference = T &;
  using const_reference = const T &;

  constexpr explicit const_list_iterator(T *p = nullptr) noexcept : _ptr(p) {}

  constexpr bool operator==(const const_list_iterator &y) const noexcept {
    return _ptr == y._ptr;
  }

  constexpr reference operator*() const noexcept { return *_ptr; }

  constexpr const value_type *operator->() const noexcept { return _ptr; }

  constexpr const_list_iterator &operator++() noexcept {
    _ptr = _ptr->*Next;
    return *this;
  }

  constexpr const_list_iterator operator++(int) noexcept {
    auto tmp = *this;
    ++(*this);
    return tmp;
  }

private:
  T *_ptr;
};