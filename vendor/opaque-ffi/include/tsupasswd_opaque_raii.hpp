#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "tsupasswd_opaque_ffi.h"

namespace tsupasswd::opaque {

class ByteBufferOwner {
public:
    ByteBufferOwner() noexcept : buf_{nullptr, 0} {}

    explicit ByteBufferOwner(ByteBuffer buf) noexcept : buf_(buf) {}

    ByteBufferOwner(const ByteBufferOwner&) = delete;
    ByteBufferOwner& operator=(const ByteBufferOwner&) = delete;

    ByteBufferOwner(ByteBufferOwner&& other) noexcept : buf_(other.buf_) {
        other.buf_.ptr = nullptr;
        other.buf_.len = 0;
    }

    ByteBufferOwner& operator=(ByteBufferOwner&& other) noexcept {
        if (this != &other) {
            reset();
            buf_ = other.buf_;
            other.buf_.ptr = nullptr;
            other.buf_.len = 0;
        }
        return *this;
    }

    ~ByteBufferOwner() { reset(); }

    ByteBuffer* out_ptr() noexcept {
        reset();
        return &buf_;
    }

    const ByteBuffer& get() const noexcept { return buf_; }

    const uint8_t* data() const noexcept { return buf_.ptr; }

    size_t size() const noexcept { return buf_.len; }

    bool empty() const noexcept { return buf_.len == 0; }

    void reset() noexcept {
        if (buf_.ptr != nullptr) {
            tsupasswd_opaque_free_bytes(buf_);
        }
        buf_.ptr = nullptr;
        buf_.len = 0;
    }

private:
    ByteBuffer buf_;
};

class ErrorStringOwner {
public:
    ErrorStringOwner() noexcept : p_(nullptr) {}

    explicit ErrorStringOwner(char* p) noexcept : p_(p) {}

    ErrorStringOwner(const ErrorStringOwner&) = delete;
    ErrorStringOwner& operator=(const ErrorStringOwner&) = delete;

    ErrorStringOwner(ErrorStringOwner&& other) noexcept : p_(other.p_) { other.p_ = nullptr; }

    ErrorStringOwner& operator=(ErrorStringOwner&& other) noexcept {
        if (this != &other) {
            reset();
            p_ = other.p_;
            other.p_ = nullptr;
        }
        return *this;
    }

    ~ErrorStringOwner() { reset(); }

    const char* c_str() const noexcept { return p_ != nullptr ? p_ : ""; }

    std::string str() const { return std::string(c_str()); }

    void reset() noexcept {
        if (p_ != nullptr) {
            tsupasswd_opaque_free_cstring(p_);
        }
        p_ = nullptr;
    }

private:
    char* p_;
};

inline std::string TakeLastErrorString() {
    ErrorStringOwner s(tsupasswd_opaque_last_error());
    return s.str();
}

} // namespace tsupasswd::opaque
