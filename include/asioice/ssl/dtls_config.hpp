#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <tuple>

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

class dtls_certificate {
  public:
    dtls_certificate();
    ~dtls_certificate();
    dtls_certificate(const dtls_certificate &) = delete;
    dtls_certificate &operator=(const dtls_certificate &) = delete;
    dtls_certificate(dtls_certificate &&) noexcept;
    dtls_certificate &operator=(dtls_certificate &&) noexcept;

    std::string get_fingerprint_sha256() const;
    void *native_handle() const noexcept;

    bool empty() const noexcept { return _impl == nullptr; }

    operator bool() const noexcept { return !empty(); }

    void clear() noexcept;

  private:
    struct impl;
    std::unique_ptr<impl> _impl;
};

} // namespace asioice::ssl
