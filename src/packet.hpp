#pragma once

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <stdexcept>

namespace ice {

class packet {
public:
  packet() = default;

  packet(std::size_t capacity) {
    if (capacity == 0)
      throw std::runtime_error{"capacity == 0"};
    _data = new std::byte[capacity];
    _size = 0;
    _capacity = capacity;
  }

  packet(const packet &other) { _copy(other); }

  packet &operator=(const packet &other) {
    if (*this != other)
      _copy(other);
    return *this;
  }

  packet(packet &&other) noexcept { _move(std::move(other)); }

  packet &operator=(packet &&other) noexcept {
    if (*this != other)
      _move(std::move(other));
    return *this;
  }

  ~packet() { _destroy(); }

  std::byte *data() noexcept { return _data; }

  const std::byte *data() const noexcept { return _data; }

  std::size_t size() const noexcept { return _size; }

  bool operator==(const packet &other) const noexcept {
    return _data == other.data();
  }

  void resize(std::size_t new_size) {
    if (new_size <= _capacity) {
      _size = new_size;
      return;
    }
    _expand(new_size);
    _size = new_size;
  }

  void clear() noexcept { _size = 0; }

private:
  void _copy(const packet &other) {
    _destroy();
    if (!other._data)
      return;
    _data = new std::byte[other._capacity];
    _capacity = other._capacity;
    _size = other.size();
    if (_size > 0)
      std::memcpy(_data, other._data, _size);
  }

  void _move(packet &&other) noexcept {
    _destroy();
    _data = std::exchange(other._data, nullptr);
    _size = std::exchange(other._size, 0);
    _capacity = std::exchange(other._capacity, 0);
  }

  void _destroy() {
    if (_data) {
      delete[] _data;
      _data = nullptr;
      _size = 0;
      _capacity = 0;
    }
  }

  void _expand(std::size_t new_capacity) {
    if (auto n = _capacity * 2 / 3; n > new_capacity)
      new_capacity = n;
    std::byte *new_data = new std::byte[new_capacity];
    _capacity = new_capacity;
    std::copy_n(_data, _size, new_data);
    delete[] _data;
    _data = new_data;
  }

  std::byte *_data{nullptr};
  std::size_t _size{0};
  std::size_t _capacity{0};
};

} // namespace ice