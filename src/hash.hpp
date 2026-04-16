#pragma once

#include <concepts>
#include <cstddef>
#include <cassert>
#include <ranges>
#include <string>
#include <string_view>

#include <boost/hash2/md5.hpp>
#include <boost/hash2/sha1.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/hash2/hmac.hpp>

namespace asioice::hash {

struct md5 {
    static constexpr std::size_t digest_size = 16;
};

struct sha1 {
    static constexpr std::size_t digest_size = 20;
};

struct sha256 {
    static constexpr std::size_t digest_size = 32;
};

struct sha512 {
    static constexpr std::size_t digest_size = 64;
};

namespace __detail {

template <class Rng>
concept is_memory_block =
    std::ranges::contiguous_range<Rng> && std::ranges::sized_range<Rng>;

template <class Algo, is_memory_block... Block>
inline void HASH(void *out, const Block &...blocks) {
    Algo algo;
    (
        [&]() {
            const void *data = std::ranges::cdata(blocks);
            const std::size_t size = std::ranges::size(blocks) *
                                     sizeof(*std::ranges::cbegin(blocks));
            algo.update((unsigned char *)data, size);
        }(),
        ...);
    auto res = algo.result();
    std::memcpy(out, res.data(), res.size());
}

} // namespace __detail

template <__detail::is_memory_block... Block>
inline void MD5(void *out, const Block &...blocks) {
    __detail::HASH<boost::hash2::md5_128>(out, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA1(void *out, const Block &...blocks) {
    __detail::HASH<boost::hash2::sha1_160>(out, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA256(void *out, const Block &...blocks) {
    __detail::HASH<boost::hash2::sha2_256>(out, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA512(void *out, const Block &...blocks) {
    __detail::HASH<boost::hash2::sha2_512>(out, blocks...);
}

template <class ALgo> struct hmac_context {};

template <> struct hmac_context<md5> {
    hmac_context(std::string_view key) : _hmac(key.data(), key.size()) {}

    hmac_context(const hmac_context &) = delete;
    hmac_context(hmac_context &&) = delete;
    hmac_context &operator=(const hmac_context &) = delete;
    hmac_context &operator=(hmac_context &&) = delete;

    void update(const void *data, std::size_t size) noexcept {
        _hmac.update((const unsigned char *)data, size);
    }

    void final(void *digest, std::size_t max_size,
               std::size_t *out_size = nullptr) noexcept {
        auto res = _hmac.result();
        std::size_t size = std::min(res.size(), max_size);
        std::memcpy(digest, res.data(), size);
        if (out_size)
            *out_size = size;
    }

  private:
    boost::hash2::hmac<boost::hash2::md5_128> _hmac;
};

template <> struct hmac_context<sha1> {
    hmac_context(std::string_view key) : _hmac(key.data(), key.size()) {}

    hmac_context(const hmac_context &) = delete;
    hmac_context(hmac_context &&) = delete;
    hmac_context &operator=(const hmac_context &) = delete;
    hmac_context &operator=(hmac_context &&) = delete;

    void update(const void *data, std::size_t size) noexcept {
        _hmac.update((const unsigned char *)data, size);
    }

    void final(void *digest, std::size_t max_size,
               std::size_t *out_size = nullptr) noexcept {
        auto res = _hmac.result();
        std::size_t size = std::min(res.size(), max_size);
        std::memcpy(digest, res.data(), size);
        if (out_size)
            *out_size = size;
    }

  private:
    boost::hash2::hmac<boost::hash2::sha1_160> _hmac;
};

template <> struct hmac_context<sha256> {
    hmac_context(std::string_view key) : _hmac(key.data(), key.size()) {}

    hmac_context(const hmac_context &) = delete;
    hmac_context(hmac_context &&) = delete;
    hmac_context &operator=(const hmac_context &) = delete;
    hmac_context &operator=(hmac_context &&) = delete;

    void update(const void *data, std::size_t size) noexcept {
        _hmac.update((const unsigned char *)data, size);
    }

    void final(void *digest, std::size_t max_size,
               std::size_t *out_size = nullptr) noexcept {
        auto res = _hmac.result();
        std::size_t size = std::min(res.size(), max_size);
        std::memcpy(digest, res.data(), size);
        if (out_size)
            *out_size = size;
    }

  private:
    boost::hash2::hmac<boost::hash2::sha2_256> _hmac;
};

template <> struct hmac_context<sha512> {
    hmac_context(std::string_view key) : _hmac(key.data(), key.size()) {}

    hmac_context(const hmac_context &) = delete;
    hmac_context(hmac_context &&) = delete;
    hmac_context &operator=(const hmac_context &) = delete;
    hmac_context &operator=(hmac_context &&) = delete;

    void update(const void *data, std::size_t size) noexcept {
        _hmac.update((const unsigned char *)data, size);
    }

    void final(void *digest, std::size_t max_size,
               std::size_t *out_size = nullptr) noexcept {
        auto res = _hmac.result();
        std::size_t size = std::min(res.size(), max_size);
        std::memcpy(digest, res.data(), size);
        if (out_size)
            *out_size = size;
    }

  private:
    boost::hash2::hmac<boost::hash2::sha2_512> _hmac;
};

void to_hex(const void *data, std::size_t size, char *out) noexcept;
std::string to_hex(const void *data, std::size_t size);

void random_bytes(void *out, std::size_t size);

} // namespace asioice::hash