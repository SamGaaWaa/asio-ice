#include "config.hpp"
#include "ssl/datagram_bio.hpp"

#include <cstring>
#include <cassert>
#include <algorithm>
#include <iostream>

namespace ice::ssl::impl {

static int __write(::BIO *b, const char *buf, int num) noexcept;
static int __read(::BIO *b, char *buf, int size) noexcept;
static int __puts(::BIO *b, const char *str) noexcept;
static long __ctrl(::BIO *b, int cmd, long arg1, void *arg2) noexcept;
static int __new(::BIO *b) noexcept;
static int __free(::BIO *b) noexcept;

static ::BIO_METHOD *BIO_ice_datagram_method() noexcept {
    struct BIO_METHOD_ptr {
        ::BIO_METHOD *method{nullptr};
        ~BIO_METHOD_ptr() noexcept {
            if (method)
                ::BIO_meth_free(method);
        }
    };
    static BIO_METHOD_ptr meth{[] {
        ::BIO_METHOD *meth = ::BIO_meth_new(BIO_TYPE_BIO, "ice_datagram");
        ::BIO_meth_set_write(meth, __write);
        ::BIO_meth_set_read(meth, __read);
        ::BIO_meth_set_puts(meth, __puts);
        ::BIO_meth_set_ctrl(meth, __ctrl);
        ::BIO_meth_set_create(meth, __new);
        ::BIO_meth_set_destroy(meth, __free);
        return meth;
    }()};
    return meth.method;
}

::BIO *datagram_bio::new_bio() {
    ::BIO *bio = ::BIO_new(BIO_ice_datagram_method());
    if (!bio)
        throw std::bad_alloc{};
    ::BIO_set_data(bio, this);
    return bio;
}

static int __write(::BIO *b, const char *buf, int num) noexcept {
    assert(buf && num > 0);
    datagram_bio *self = static_cast<datagram_bio*>(::BIO_get_data(b));
    assert(self);

    ::BIO_clear_retry_flags(b);
    if (self->last_io_failed()) {
        return -1;
    }
    if (!self->out.empty()) {
        ::BIO_set_retry_write(b);
        return -1;
    }
    self->out.resize(num);
    std::copy(buf, buf + num, (char*)self->out.data());
    return num;
}

static int __read(::BIO *b, char *buf, int size) noexcept {
    assert(buf && size > 0);
    datagram_bio *self = static_cast<datagram_bio*>(::BIO_get_data(b));
    assert(self);

    ::BIO_clear_retry_flags(b);
    if (self->in.empty()) {
        ::BIO_set_retry_read(b);
        return -1;
    }
    std::size_t nread = size > self->in->size() ? self->in->size() : size;
    std::memcpy(buf, self->in->data(), nread);
    ICE_IN_DEBUG {
        if (nread < self->in->size())
            std::cout << "BIO_ice_datagram_method::read: drop " << self->in->size() - nread << " bytes\n";
    }
    self->in.reset();
    return nread;
}

static int __puts(::BIO *b, const char *str) noexcept {
    assert(str);
    return __write(b, str, std::strlen(str));
}

static long __ctrl(::BIO *b, int cmd, long arg1, void *arg2) noexcept {
    datagram_bio *self = static_cast<datagram_bio*>(::BIO_get_data(b));
    assert(self);
    switch (cmd) {
    case BIO_CTRL_RESET:
        std::vector<uint8_t>{}.swap(self->out);
        self->in.reset();
        return 0;
    case BIO_CTRL_EOF:
        return 0;
    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
        return 0;
    case BIO_CTRL_DGRAM_QUERY_MTU:
        return 1200;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
    std::unreachable();
}

static int __new(::BIO *b) noexcept {
    ::BIO_set_shutdown(b, 0);
    ::BIO_set_init(b, 1);
    ::BIO_set_data(b, 0);
    return 1;
}

static int __free(::BIO *b) noexcept {
    if (!b)
        return 0;
    return 1;
}

} // namespace ice::ssl::impl