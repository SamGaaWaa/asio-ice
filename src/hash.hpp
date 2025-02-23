#pragma once

#include <concepts>
#include <cstddef>
#include <ranges>
#include <string_view>

namespace ice::hash {

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

void md5_init();
void md5_update(const void *data, std::size_t size) noexcept;
void md5_final(void *digest) noexcept;

void sha1_init();
void sha1_update(const void *data, std::size_t size) noexcept;
void sha1_final(void *digest) noexcept;

void sha256_init();
void sha256_update(const void *data, std::size_t size) noexcept;
void sha256_final(void *digest) noexcept;

void sha512_init();
void sha512_update(const void *data, std::size_t size) noexcept;
void sha512_final(void *digest) noexcept;

template <class Rng>
concept is_memory_block =
    std::ranges::contiguous_range<Rng> && std::ranges::sized_range<Rng>;

template <is_memory_block... Block>
inline void HASH(void *out, auto init_fn, auto update_fn, auto final_fn,
                 const Block &...blocks) {
    init_fn();
    (
        [&]() {
            const void *data = std::ranges::cdata(blocks);
            const std::size_t size = std::ranges::size(blocks) *
                                     sizeof(*std::ranges::cbegin(blocks));
            update_fn(data, size);
        }(),
        ...);
    final_fn(out);
}

} // namespace __detail

template <__detail::is_memory_block... Block>
inline void MD5(void *out, const Block &...blocks) {
    __detail::HASH(out, __detail::md5_init, __detail::md5_update,
                   __detail::md5_final, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA1(void *out, const Block &...blocks) {
    __detail::HASH(out, __detail::sha1_init, __detail::sha1_update,
                   __detail::sha1_final, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA256(void *out, const Block &...blocks) {
    __detail::HASH(out, __detail::sha256_init, __detail::sha256_update,
                   __detail::sha256_final, blocks...);
}

template <__detail::is_memory_block... Block>
inline void SHA512(void *out, const Block &...blocks) {
    __detail::HASH(out, __detail::sha512_init, __detail::sha512_update,
                   __detail::sha512_final, blocks...);
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

std::string to_hex(const void *data, std::size_t size);

} // namespace ice::hash