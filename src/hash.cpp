#include "hash.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace ice::hash {

namespace __detail {

struct EVP_MD_CTX_ptr {
    EVP_MD_CTX_ptr() {
        _ctx = ::EVP_MD_CTX_new();
        if (!_ctx) {
            throw std::bad_alloc();
        }
    }

    EVP_MD_CTX_ptr(const EVP_MD_CTX_ptr &) = delete;
    EVP_MD_CTX_ptr &operator=(const EVP_MD_CTX_ptr &) = delete;

    EVP_MD_CTX_ptr(EVP_MD_CTX_ptr &&other) noexcept
        : _ctx(std::exchange(other._ctx, nullptr)) {}

    EVP_MD_CTX_ptr &operator=(EVP_MD_CTX_ptr &&other) noexcept {
        if (this != &other) {
            if (_ctx)
                ::EVP_MD_CTX_free(_ctx);
            _ctx = std::exchange(other._ctx, nullptr);
        }
        return *this;
    }

    const ::EVP_MD_CTX *get() const noexcept { return _ctx; }

    ::EVP_MD_CTX *get() noexcept { return _ctx; }

    ~EVP_MD_CTX_ptr() {
        if (_ctx)
            ::EVP_MD_CTX_free(_ctx);
    }

  private:
    ::EVP_MD_CTX *_ctx = nullptr;
};

struct EVP_MAC_ptr {
    EVP_MAC_ptr(const char *name) {
        _mac = ::EVP_MAC_fetch(NULL, name, NULL);
        if (!_mac) {
            throw std::runtime_error("EVP_MAC_fetch failed");
        }
    }

    EVP_MAC_ptr(const EVP_MAC_ptr &) = delete;
    EVP_MAC_ptr &operator=(const EVP_MAC_ptr &) = delete;

    EVP_MAC_ptr(EVP_MAC_ptr &&other) noexcept
        : _mac(std::exchange(other._mac, nullptr)) {}

    EVP_MAC_ptr &operator=(EVP_MAC_ptr &&other) noexcept {
        if (this != &other) {
            if (_mac)
                ::EVP_MAC_free(_mac);
            _mac = std::exchange(other._mac, nullptr);
        }
        return *this;
    }

    const ::EVP_MAC *get() const noexcept { return _mac; }

    ::EVP_MAC *get() noexcept { return _mac; }

    ~EVP_MAC_ptr() {
        if (_mac)
            ::EVP_MAC_free(_mac);
    }

  private:
    ::EVP_MAC *_mac = nullptr;
};

struct EVP_MAC_CTX_ptr {
    EVP_MAC_CTX_ptr(EVP_MAC *mac) {
        _ctx = ::EVP_MAC_CTX_new(mac);
        if (!_ctx) {
            throw std::bad_alloc();
        }
    }

    EVP_MAC_CTX_ptr(const EVP_MAC_CTX_ptr &other) = delete;
    EVP_MAC_CTX_ptr &operator=(const EVP_MAC_CTX_ptr &other) = delete;

    EVP_MAC_CTX_ptr(EVP_MAC_CTX_ptr &&other) noexcept
        : _ctx(std::exchange(other._ctx, nullptr)) {}

    EVP_MAC_CTX_ptr &operator=(EVP_MAC_CTX_ptr &&other) noexcept {
        if (this != &other) {
            if (_ctx)
                ::EVP_MAC_CTX_free(_ctx);
            _ctx = std::exchange(other._ctx, nullptr);
        }
        return *this;
    }

    const ::EVP_MAC_CTX *get() const noexcept { return _ctx; }

    ::EVP_MAC_CTX *get() noexcept { return _ctx; }

    ~EVP_MAC_CTX_ptr() {
        if (_ctx)
            ::EVP_MAC_CTX_free(_ctx);
    }

  private:
    ::EVP_MAC_CTX *_ctx = nullptr;
};

static thread_local EVP_MD_CTX_ptr s_md5_ctx;
static thread_local EVP_MD_CTX_ptr s_sha1_ctx;
static thread_local EVP_MD_CTX_ptr s_sha256_ctx;
static thread_local EVP_MD_CTX_ptr s_sha512_ctx;

static thread_local EVP_MAC_ptr s_hmac("HMAC");

static thread_local EVP_MAC_CTX_ptr s_hmac_md5_ctx(s_hmac.get());
static thread_local EVP_MAC_CTX_ptr s_hmac_sha1_ctx(s_hmac.get());
static thread_local EVP_MAC_CTX_ptr s_hmac_sha256_ctx(s_hmac.get());
static thread_local EVP_MAC_CTX_ptr s_hmac_sha512_ctx(s_hmac.get());

void md5_init() {
    if (!::EVP_DigestInit_ex2(s_md5_ctx.get(), ::EVP_md5(), nullptr)) {
        throw std::runtime_error("EVP_DigestInit_ex2 failed");
    }
}

void md5_update(const void *data, std::size_t size) noexcept {
    ::EVP_DigestUpdate(s_md5_ctx.get(), data, size);
}
void md5_final(void *digest) noexcept {
    ::EVP_DigestFinal(s_md5_ctx.get(), (unsigned char *)digest, nullptr);
}

void sha1_init() {
    if (!::EVP_DigestInit_ex2(s_sha1_ctx.get(), ::EVP_sha1(), nullptr)) {
        throw std::runtime_error("EVP_DigestInit_ex2 failed");
    }
}

void sha1_update(const void *data, std::size_t size) noexcept {
    ::EVP_DigestUpdate(s_sha1_ctx.get(), data, size);
}

void sha1_final(void *digest) noexcept {
    ::EVP_DigestFinal(s_sha1_ctx.get(), (unsigned char *)digest, nullptr);
}

void sha256_init() {
    if (!::EVP_DigestInit_ex2(s_sha256_ctx.get(), ::EVP_sha256(), nullptr)) {
        throw std::runtime_error("EVP_DigestInit_ex2 failed");
    }
}

void sha256_update(const void *data, std::size_t size) noexcept {
    ::EVP_DigestUpdate(s_sha256_ctx.get(), data, size);
}

void sha256_final(void *digest) noexcept {
    ::EVP_DigestFinal(s_sha256_ctx.get(), (unsigned char *)digest, nullptr);
}

void sha512_init() {
    if (!::EVP_DigestInit_ex2(s_sha512_ctx.get(), ::EVP_sha512(), nullptr)) {
        throw std::runtime_error("EVP_DigestInit_ex2 failed");
    }
}

void sha512_update(const void *data, std::size_t size) noexcept {
    ::EVP_DigestUpdate(s_sha512_ctx.get(), data, size);
}

void sha512_final(void *digest) noexcept {
    ::EVP_DigestFinal(s_sha512_ctx.get(), (unsigned char *)digest, nullptr);
}

} // namespace __detail

// hmac-md5
template <> hmac_context<md5>::hmac_context(std::string_view key) {
    OSSL_PARAM params[2];
    char algo[] = "MD5";
    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, algo, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!::EVP_MAC_init(__detail::s_hmac_md5_ctx.get(),
                        (const unsigned char *)key.data(), key.size(),
                        params)) {
        throw std::runtime_error("Failed to initialize HMAC-MD5 context");
    }
}

template <>
void hmac_context<md5>::update(const void *data, std::size_t size) noexcept {
    ::EVP_MAC_update(__detail::s_hmac_md5_ctx.get(),
                     (const unsigned char *)data, size);
}

template <>
void hmac_context<md5>::final(void *digest, std::size_t max_size,
                              std::size_t *out_size) noexcept {
    ::EVP_MAC_final(__detail::s_hmac_md5_ctx.get(), (unsigned char *)digest,
                    out_size, max_size);
}

template <> hmac_context<md5>::~hmac_context() noexcept {}

// hmac-sha1
template <> hmac_context<sha1>::hmac_context(std::string_view key) {
    OSSL_PARAM params[2];
    char algo[] = "SHA1";
    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, algo, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!::EVP_MAC_init(__detail::s_hmac_sha1_ctx.get(),
                        (const unsigned char *)key.data(), key.size(),
                        params)) {
        throw std::runtime_error("Failed to initialize HMAC-SHA1 context");
    }
}

template <>
void hmac_context<sha1>::update(const void *data, std::size_t size) noexcept {
    ::EVP_MAC_update(__detail::s_hmac_sha1_ctx.get(),
                     (const unsigned char *)data, size);
}

template <>
void hmac_context<sha1>::final(void *digest, std::size_t max_size,
                               std::size_t *out_size) noexcept {
    ::EVP_MAC_final(__detail::s_hmac_sha1_ctx.get(), (unsigned char *)digest,
                    out_size, max_size);
}

template <> hmac_context<sha1>::~hmac_context() noexcept {}

// hmac-sha256
template <> hmac_context<sha256>::hmac_context(std::string_view key) {
    OSSL_PARAM params[2];
    char algo[] = "SHA256";
    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, algo, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!::EVP_MAC_init(__detail::s_hmac_sha256_ctx.get(),
                        (const unsigned char *)key.data(), key.size(),
                        params)) {
        throw std::runtime_error("Failed to initialize HMAC-SHA1 context");
    }
}

template <>
void hmac_context<sha256>::update(const void *data, std::size_t size) noexcept {
    ::EVP_MAC_update(__detail::s_hmac_sha256_ctx.get(),
                     (const unsigned char *)data, size);
}

template <>
void hmac_context<sha256>::final(void *digest, std::size_t max_size,
                                 std::size_t *out_size) noexcept {
    ::EVP_MAC_final(__detail::s_hmac_sha256_ctx.get(), (unsigned char *)digest,
                    out_size, max_size);
}

template <> hmac_context<sha256>::~hmac_context() noexcept {}

// hmac-sha512
template <> hmac_context<sha512>::hmac_context(std::string_view key) {
    OSSL_PARAM params[2];
    char algo[] = "SHA512";
    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, algo, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!::EVP_MAC_init(__detail::s_hmac_sha512_ctx.get(),
                        (const unsigned char *)key.data(), key.size(),
                        params)) {
        throw std::runtime_error("Failed to initialize HMAC-SHA1 context");
    }
}

template <>
void hmac_context<sha512>::update(const void *data, std::size_t size) noexcept {
    ::EVP_MAC_update(__detail::s_hmac_sha512_ctx.get(),
                     (const unsigned char *)data, size);
}

template <>
void hmac_context<sha512>::final(void *digest, std::size_t max_size,
                                 std::size_t *out_size) noexcept {
    ::EVP_MAC_final(__detail::s_hmac_sha512_ctx.get(), (unsigned char *)digest,
                    out_size, max_size);
}

template <> hmac_context<sha512>::~hmac_context() noexcept {}

template struct hmac_context<md5>;
template struct hmac_context<sha1>;
template struct hmac_context<sha256>;
template struct hmac_context<sha512>;

void to_hex(const void *data, std::size_t size, char *out) noexcept {
    const uint8_t *begin = (const uint8_t *)data;
    const uint8_t *const end = begin + size;
    for (; begin != end; ++begin) {
        const uint8_t byte = *begin;
        *out++ = "0123456789abcdef"[byte >> 4];
        *out++ = "0123456789abcdef"[byte & 0x0f];
    }
}

std::string to_hex(const void *data, std::size_t size) {
    std::string res;
    res.resize_and_overwrite(2 * size,
                             [&](char *p, std::size_t n) -> std::size_t {
                                 to_hex(data, size, p);
                                 return 2 * size;
                             });
    return res;
}

} // namespace ice::hash