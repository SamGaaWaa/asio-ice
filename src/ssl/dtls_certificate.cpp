#include "asioice/ssl/dtls_config.hpp"
#include "asioice/detail/scope_guard.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/bio.h>

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cassert>
#include <utility>

namespace asioice::ssl {

struct dtls_certificate::impl {
    ::SSL_CTX *ctx{nullptr};
    ::X509 *cert{nullptr};
    ::EVP_PKEY *pkey{nullptr};
};

namespace {

// ---------------------------------------------------------------------------
// fingerprint helpers
// ---------------------------------------------------------------------------

constexpr const ::EVP_MD *to_evp_md(hash_algorithm algo) noexcept {
    switch (algo) {
    case hash_algorithm::sha1:
        return ::EVP_sha1();
    case hash_algorithm::sha256:
        return ::EVP_sha256();
    case hash_algorithm::sha384:
        return ::EVP_sha384();
    case hash_algorithm::sha512:
        return ::EVP_sha512();
    }
    return ::EVP_sha256();
}

static std::string compute_fingerprint(::X509 *cert,
                                       hash_algorithm algo) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    if (!::X509_digest(cert, to_evp_md(algo), md, &n))
        throw std::runtime_error{"X509_digest failed"};
    std::ostringstream oss;
    for (unsigned int i = 0; i < n; ++i) {
        if (i != 0)
            oss << ":";
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
            << static_cast<int>(md[i]);
    }
    return std::move(oss).str();
}

} // namespace

// ---------------------------------------------------------------------------
// fingerprint struct methods (must be at asioice::ssl scope)
// ---------------------------------------------------------------------------

std::string fingerprint::hash_name() const {
    switch (algorithm) {
    case hash_algorithm::sha1:
        return "sha-1";
    case hash_algorithm::sha256:
        return "sha-256";
    case hash_algorithm::sha384:
        return "sha-384";
    case hash_algorithm::sha512:
        return "sha-512";
    }
    return "sha-256";
}

std::string fingerprint::to_sdp() const {
    return hash_name() + " " + value;
}

std::optional<fingerprint> fingerprint::from_sdp(std::string_view line) {
    fingerprint fp;
    if (line.starts_with("sha-1 ")) {
        fp.algorithm = hash_algorithm::sha1;
        fp.value = line.substr(6);
    } else if (line.starts_with("sha-256 ")) {
        fp.algorithm = hash_algorithm::sha256;
        fp.value = line.substr(8);
    } else if (line.starts_with("sha-384 ")) {
        fp.algorithm = hash_algorithm::sha384;
        fp.value = line.substr(8);
    } else if (line.starts_with("sha-512 ")) {
        fp.algorithm = hash_algorithm::sha512;
        fp.value = line.substr(8);
    } else {
        return std::nullopt;
    }
    std::transform(fp.value.begin(), fp.value.end(), fp.value.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return fp;
}

// ---------------------------------------------------------------------------
// key / certificate generation
// ---------------------------------------------------------------------------

namespace {

static ::EVP_PKEY *generate_ec_key(int curve_nid) noexcept {
    ::EVP_PKEY_CTX *pctx = ::EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx)
        return nullptr;
    utils::scope_guard pctx_guard{
        [pctx]() noexcept { ::EVP_PKEY_CTX_free(pctx); }};
    if (::EVP_PKEY_keygen_init(pctx) <= 0)
        return nullptr;
    if (::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0)
        return nullptr;
    ::EVP_PKEY *pkey = nullptr;
    if (::EVP_PKEY_keygen(pctx, &pkey) <= 0)
        return nullptr;
    pctx_guard.dismiss();
    return pkey;
}

static ::EVP_PKEY *generate_ed25519_key() noexcept {
    ::EVP_PKEY_CTX *pctx = ::EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx)
        return nullptr;
    utils::scope_guard pctx_guard{
        [pctx]() noexcept { ::EVP_PKEY_CTX_free(pctx); }};
    if (::EVP_PKEY_keygen_init(pctx) <= 0)
        return nullptr;
    ::EVP_PKEY *pkey = nullptr;
    if (::EVP_PKEY_keygen(pctx, &pkey) <= 0)
        return nullptr;
    pctx_guard.dismiss();
    return pkey;
}

static ::EVP_PKEY *generate_key(key_type kt) noexcept {
    switch (kt) {
    case key_type::ecdsa_p256:
        return generate_ec_key(NID_X9_62_prime256v1);
    case key_type::ecdsa_p384:
        return generate_ec_key(NID_secp384r1);
    case key_type::ed25519:
        return generate_ed25519_key();
    }
    return nullptr;
}

static bool generate_self_signed_cert(::X509 *&out_cert,
                                      ::EVP_PKEY *&out_pkey,
                                      key_type kt,
                                      hash_algorithm sign_algo) noexcept {
    out_cert = nullptr;
    out_pkey = nullptr;

    out_pkey = generate_key(kt);
    if (!out_pkey)
        return false;
    utils::scope_guard out_pkey_guard{[&out_pkey]() noexcept {
        ::EVP_PKEY_free(out_pkey);
        out_pkey = nullptr;
    }};

    out_cert = ::X509_new();
    if (!out_cert)
        return false;
    utils::scope_guard out_cert_guard{[&out_cert]() noexcept {
        ::X509_free(out_cert);
        out_cert = nullptr;
    }};

    ::X509_set_version(out_cert, 2);
    ::ASN1_INTEGER_set(::X509_get_serialNumber(out_cert), 1);

    ::X509_gmtime_adj(::X509_getm_notBefore(out_cert), -3600 * 24 * 365);
    ::X509_gmtime_adj(::X509_getm_notAfter(out_cert), 3600 * 24 * 365 * 10);

    ::X509_set_pubkey(out_cert, out_pkey);

    ::X509_NAME *name = ::X509_get_subject_name(out_cert);
    ::X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                 (const unsigned char *)"asio-ice", -1, -1, 0);
    ::X509_set_issuer_name(out_cert, name);

    if (::X509_sign(out_cert, out_pkey, to_evp_md(sign_algo)) <= 0)
        return false;
    out_pkey_guard.dismiss();
    out_cert_guard.dismiss();
    return true;
}

// ---------------------------------------------------------------------------
// SSL_CTX helper
// ---------------------------------------------------------------------------

static ::SSL_CTX *make_ssl_ctx() {
    ::SSL_CTX *ctx = ::SSL_CTX_new(::DTLS_method());
    if (!ctx)
        throw std::runtime_error{"SSL_CTX_new(DTLS_method) failed"};
    return ctx;
}

static void configure_ssl_ctx(::SSL_CTX *ctx) {
    ::SSL_CTX_set_read_ahead(ctx, 1);
    ::SSL_CTX_set_verify(
        ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    ::SSL_CTX_set_tlsext_use_srtp(
        ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32:"
             "SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM");
    static const unsigned char alpn[] = "\x06"
                                        "webrtc";
    ::SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1);
}

static void attach_cert_to_ctx(::SSL_CTX *ctx, ::X509 *cert,
                                ::EVP_PKEY *pkey) {
    if (::SSL_CTX_use_certificate(ctx, cert) <= 0)
        throw std::runtime_error{"SSL_CTX_use_certificate failed"};
    if (::SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
        throw std::runtime_error{"SSL_CTX_use_PrivateKey failed"};
    if (::SSL_CTX_check_private_key(ctx) <= 0)
        throw std::runtime_error{"SSL_CTX_check_private_key failed"};
}

} // namespace

// ---------------------------------------------------------------------------
// dtls_certificate — constructors
// ---------------------------------------------------------------------------

dtls_certificate::dtls_certificate(key_type kt, hash_algorithm sign_algo)
    : _impl{std::make_unique<impl>()} {
    _impl->ctx = make_ssl_ctx();
    utils::scope_guard ctx_guard{[this]() noexcept {
        ::SSL_CTX_free(_impl->ctx);
        _impl->ctx = nullptr;
    }};
    configure_ssl_ctx(_impl->ctx);
    if (!generate_self_signed_cert(_impl->cert, _impl->pkey, kt, sign_algo))
        throw std::runtime_error{"generate_self_signed_cert failed"};
    attach_cert_to_ctx(_impl->ctx, _impl->cert, _impl->pkey);
    ctx_guard.dismiss();
}

dtls_certificate::dtls_certificate(std::unique_ptr<impl> impl)
    : _impl{std::move(impl)} {}

// ---------------------------------------------------------------------------
// dtls_certificate — PEM / DER loading
// ---------------------------------------------------------------------------

dtls_certificate dtls_certificate::from_pem(std::string_view cert_pem,
                                             std::string_view key_pem) {
    ::BIO *cert_bio = ::BIO_new_mem_buf(cert_pem.data(),
                                         static_cast<int>(cert_pem.size()));
    if (!cert_bio)
        throw std::runtime_error{"BIO_new_mem_buf(cert) failed"};
    ::X509 *cert =
        ::PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    ::BIO_free(cert_bio);
    if (!cert)
        throw std::runtime_error{"PEM_read_bio_X509 failed"};
    utils::scope_guard cert_guard{
        [cert]() noexcept { ::X509_free(cert); }};

    ::BIO *key_bio = ::BIO_new_mem_buf(key_pem.data(),
                                        static_cast<int>(key_pem.size()));
    if (!key_bio)
        throw std::runtime_error{"BIO_new_mem_buf(key) failed"};
    ::EVP_PKEY *pkey =
        ::PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    ::BIO_free(key_bio);
    if (!pkey)
        throw std::runtime_error{"PEM_read_bio_PrivateKey failed"};
    utils::scope_guard pkey_guard{
        [pkey]() noexcept { ::EVP_PKEY_free(pkey); }};

    auto impl = std::make_unique<dtls_certificate::impl>();
    impl->ctx = make_ssl_ctx();
    utils::scope_guard ctx_guard{[&impl]() noexcept {
        ::SSL_CTX_free(impl->ctx);
        impl->ctx = nullptr;
    }};
    configure_ssl_ctx(impl->ctx);
    impl->cert = cert;
    impl->pkey = pkey;
    attach_cert_to_ctx(impl->ctx, impl->cert, impl->pkey);
    cert_guard.dismiss();
    pkey_guard.dismiss();
    ctx_guard.dismiss();
    return dtls_certificate{std::move(impl)};
}

dtls_certificate dtls_certificate::from_der(
    std::span<const uint8_t> cert_der, std::span<const uint8_t> key_der) {
    const unsigned char *cert_ptr = cert_der.data();
    ::X509 *cert = ::d2i_X509(nullptr, &cert_ptr,
                              static_cast<long>(cert_der.size()));
    if (!cert)
        throw std::runtime_error{"d2i_X509 failed"};
    utils::scope_guard cert_guard{
        [cert]() noexcept { ::X509_free(cert); }};

    const unsigned char *key_ptr = key_der.data();
    ::EVP_PKEY *pkey = ::d2i_AutoPrivateKey(
        nullptr, &key_ptr, static_cast<long>(key_der.size()));
    if (!pkey)
        throw std::runtime_error{"d2i_AutoPrivateKey failed"};
    utils::scope_guard pkey_guard{
        [pkey]() noexcept { ::EVP_PKEY_free(pkey); }};

    auto impl = std::make_unique<dtls_certificate::impl>();
    impl->ctx = make_ssl_ctx();
    utils::scope_guard ctx_guard{[&impl]() noexcept {
        ::SSL_CTX_free(impl->ctx);
        impl->ctx = nullptr;
    }};
    configure_ssl_ctx(impl->ctx);
    impl->cert = cert;
    impl->pkey = pkey;
    attach_cert_to_ctx(impl->ctx, impl->cert, impl->pkey);
    cert_guard.dismiss();
    pkey_guard.dismiss();
    ctx_guard.dismiss();
    return dtls_certificate{std::move(impl)};
}

// ---------------------------------------------------------------------------
// dtls_certificate — fingerprints
// ---------------------------------------------------------------------------

fingerprint dtls_certificate::get_fingerprint(hash_algorithm algo) const {
    assert(_impl && _impl->cert);
    return fingerprint{algo, compute_fingerprint(_impl->cert, algo)};
}

// ---------------------------------------------------------------------------
// dtls_certificate — PEM export
// ---------------------------------------------------------------------------

std::string dtls_certificate::cert_pem() const {
    assert(_impl && _impl->cert);
    ::BIO *bio = ::BIO_new(::BIO_s_mem());
    utils::scope_guard bio_guard{
        [bio]() noexcept { ::BIO_free(bio); }};
    if (::PEM_write_bio_X509(bio, _impl->cert) <= 0)
        throw std::runtime_error{"PEM_write_bio_X509 failed"};
    char *data = nullptr;
    long len = ::BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<size_t>(len));
}

std::string dtls_certificate::key_pem() const {
    assert(_impl && _impl->pkey);
    ::BIO *bio = ::BIO_new(::BIO_s_mem());
    utils::scope_guard bio_guard{
        [bio]() noexcept { ::BIO_free(bio); }};
    if (::PEM_write_bio_PrivateKey(bio, _impl->pkey, nullptr, nullptr, 0,
                                   nullptr, nullptr) <= 0)
        throw std::runtime_error{"PEM_write_bio_PrivateKey failed"};
    char *data = nullptr;
    long len = ::BIO_get_mem_data(bio, &data);
    return std::string(data, static_cast<size_t>(len));
}

// ---------------------------------------------------------------------------
// dtls_certificate — move / dtor / clear
// ---------------------------------------------------------------------------

dtls_certificate::~dtls_certificate() { clear(); }

dtls_certificate::dtls_certificate(dtls_certificate &&other) noexcept
    : _impl{std::exchange(other._impl, nullptr)} {}

dtls_certificate &
dtls_certificate::operator=(dtls_certificate &&other) noexcept {
    if (this != &other) {
        clear();
        _impl = std::exchange(other._impl, nullptr);
    }
    return *this;
}

void *dtls_certificate::native_handle() const noexcept {
    return static_cast<void *>(_impl->ctx);
}

void dtls_certificate::clear() noexcept {
    if (!_impl)
        return;
    if (_impl->cert)
        ::X509_free(_impl->cert);
    if (_impl->pkey)
        ::EVP_PKEY_free(_impl->pkey);
    if (_impl->ctx)
        ::SSL_CTX_free(_impl->ctx);
    _impl = nullptr;
}

} // namespace asioice::ssl
