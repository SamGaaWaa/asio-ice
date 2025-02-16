#pragma once

#include <concepts>
#include <cstddef>
#include <ranges>
#include <string_view>

namespace ice::hash {

struct md5 {};
struct sha1 {};
struct sha256 {};
struct sha512 {};

namespace __detail {

void md5_update(const void *data, std::size_t size) noexcept;
void md5_final(void *digest) noexcept;

void sha1_update(const void *data, std::size_t size) noexcept;
void sha1_final(void *digest) noexcept;

void sha256_update(const void *data, std::size_t size) noexcept;
void sha256_final(void *digest) noexcept;

void sha512_update(const void *data, std::size_t size) noexcept;
void sha512_final(void *digest) noexcept;

template <class Rng>
concept is_memory_block =
    std::ranges::contiguous_range<Rng> && std::ranges::sized_range<Rng>;

template <is_memory_block... Block>
inline void HASH(void *out, auto update_fn, auto final_fn, Block... blocks) {
    (
        [&]() {
            const void *data = std::ranges::cdata(blocks);
            const std::size_t size =
                std::ranges::size(blocks) * sizeof(*std::ranges::begin(blocks));
            update_fn(data, size);
        }(),
        ...);
    final_fn(out);
}

} // namespace __detail

template <__detail::is_memory_block... Block>
inline void MD5(void *out, Block... blocks) {
    __detail::HASH(out, __detail::md5_update, __detail::md5_final, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA1(void *out, Block... blocks) {
    __detail::HASH(out, __detail::sha1_update, __detail::sha1_final, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA256(void *out, Block... blocks) {
    __detail::HASH(out, __detail::sha256_update, __detail::sha256_final,
                   blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA512(void *out, Block... blocks) {
    __detail::HASH(out, __detail::sha512_update, __detail::sha512_final,
                   blocks...);
}

template <class ALgo> struct hmac_context {
    hmac_context(std::string_view key);
    hmac_context(const hmac_context &) = delete;
    hmac_context(hmac_context &&) = delete;
    hmac_context &operator=(const hmac_context &) = delete;
    hmac_context &operator=(hmac_context &&) = delete;

    void update(const void *data, std::size_t size) noexcept;
    void final(void *digest, std::size_t max_size,
               std::size_t *out_size = nullptr) noexcept;

    ~hmac_context() noexcept;
};

void to_hex(const void *data, std::size_t size, char *out) noexcept;

} // namespace ice::hash