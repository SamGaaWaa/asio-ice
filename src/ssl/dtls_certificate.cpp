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
static std::string compute_sha256_fingerprint(::X509 *cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    if (!::X509_digest(cert, ::EVP_sha256(), md, &n))
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

static bool generate_self_signed_cert(::X509 *&out_cert,
                                      ::EVP_PKEY *&out_pkey) noexcept {
    out_cert = nullptr;
    out_pkey = nullptr;

    ::EVP_PKEY_CTX *pctx = ::EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx)
        return false;
    utils::scope_guard pctx_guard{
        [pctx]() noexcept { ::EVP_PKEY_CTX_free(pctx); }};
    if (::EVP_PKEY_keygen_init(pctx) <= 0)
        return false;
    if (::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <=
        0)
        return false;

    if (::EVP_PKEY_keygen(pctx, &out_pkey) <= 0)
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

    if (::X509_sign(out_cert, out_pkey, ::EVP_sha256()) <= 0)
        return false;
    out_pkey_guard.dismiss();
    out_cert_guard.dismiss();
    return true;
}
} // namespace

dtls_certificate::dtls_certificate() : _impl{std::make_unique<impl>()} {
    _impl->ctx = ::SSL_CTX_new(::DTLS_method());
    if (!_impl->ctx)
        throw std::runtime_error{"SSL_CTX_new(DTLS_method) failed"};

    ::SSL_CTX_set_read_ahead(_impl->ctx, 1);

    ::SSL_CTX_set_verify(
        _impl->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    ::SSL_CTX_set_tlsext_use_srtp(
        _impl->ctx, "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32:"
                    "SRTP_AEAD_AES_128_GCM:SRTP_AEAD_AES_256_GCM");

    static const unsigned char alpn[] = "\x06"
                                        "webrtc";
    ::SSL_CTX_set_alpn_protos(_impl->ctx, alpn, sizeof(alpn) - 1);

    if (!generate_self_signed_cert(_impl->cert, _impl->pkey))
        throw std::runtime_error{"generate_self_signed_cert failed"};

    if (::SSL_CTX_use_certificate(_impl->ctx, _impl->cert) <= 0)
        throw std::runtime_error{"SSL_CTX_use_certificate failed"};
    if (::SSL_CTX_use_PrivateKey(_impl->ctx, _impl->pkey) <= 0)
        throw std::runtime_error{"SSL_CTX_use_PrivateKey failed"};
    if (::SSL_CTX_check_private_key(_impl->ctx) <= 0)
        throw std::runtime_error{"SSL_CTX_check_private_key failed"};
}

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

std::string dtls_certificate::get_fingerprint_sha256() const {
    assert(_impl && _impl->cert);
    return compute_sha256_fingerprint(_impl->cert);
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
