#pragma once

#include <vector>
#include <string>
#include <string_view>
#include <cstdint>
#include <memory>
#include <tuple>
#include <span>
#include <optional>

namespace asioice::ssl {

enum class srtp_protection_profile {
    srtp_aes128_cm_sha1_80,
    srtp_aes128_cm_sha1_32,
    srtp_aead_aes_128_gcm,
    srtp_aead_aes_256_gcm,
    none
};

struct srtp_key_material {
    std::vector<uint8_t> client_write_key;
    std::vector<uint8_t> server_write_key;
    std::vector<uint8_t> client_write_salt;
    std::vector<uint8_t> server_write_salt;
    srtp_protection_profile profile = srtp_protection_profile::none;
};

enum class dtls_role { client, server };

enum class hash_algorithm {
    sha1,
    sha256,
    sha384,
    sha512,
};

enum class key_type {
    ecdsa_p256,
    ecdsa_p384,
    ed25519,
};

struct fingerprint {
    hash_algorithm algorithm = hash_algorithm::sha256;
    std::string value;

    bool empty() const noexcept { return value.empty(); }

    std::string hash_name() const;

    std::string to_sdp() const;

    static std::optional<fingerprint>
    from_sdp(std::string_view sdp_line);

    std::strong_ordering
    operator<=>(const fingerprint &) const noexcept = default;
};

class dtls_certificate {
  public:
    dtls_certificate(key_type kt = key_type::ecdsa_p256,
                     hash_algorithm sign_algo = hash_algorithm::sha256);

    static dtls_certificate
    from_pem(std::string_view cert_pem, std::string_view key_pem);

    static dtls_certificate
    from_der(std::span<const uint8_t> cert_der,
             std::span<const uint8_t> key_der);

    ~dtls_certificate();
    dtls_certificate(const dtls_certificate &) = delete;
    dtls_certificate &operator=(const dtls_certificate &) = delete;
    dtls_certificate(dtls_certificate &&) noexcept;
    dtls_certificate &operator=(dtls_certificate &&) noexcept;

    fingerprint get_fingerprint(hash_algorithm algo) const;

    std::string cert_pem() const;
    std::string key_pem() const;

    void *native_handle() const noexcept;

    bool empty() const noexcept { return _impl == nullptr; }

    operator bool() const noexcept { return !empty(); }

    void clear() noexcept;

  private:
    struct impl;
    std::unique_ptr<impl> _impl;

    dtls_certificate(std::unique_ptr<impl> impl);
};

} // namespace asioice::ssl
