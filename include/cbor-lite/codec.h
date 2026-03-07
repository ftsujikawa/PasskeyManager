#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>

namespace CborLite
{
    namespace detail
    {
        template <typename ByteT>
        inline void append(std::vector<ByteT>& out, uint8_t b)
        {
            out.push_back(static_cast<ByteT>(b));
        }

        template <typename ByteT>
        inline size_t encode_type_and_length(std::vector<ByteT>& out, uint8_t majorType, uint64_t value)
        {
            const size_t before = out.size();
            const uint8_t mt = static_cast<uint8_t>(majorType << 5);

            if (value <= 23)
            {
                append(out, static_cast<uint8_t>(mt | static_cast<uint8_t>(value)));
            }
            else if (value <= 0xFF)
            {
                append(out, static_cast<uint8_t>(mt | 24));
                append(out, static_cast<uint8_t>(value));
            }
            else if (value <= 0xFFFF)
            {
                append(out, static_cast<uint8_t>(mt | 25));
                append(out, static_cast<uint8_t>((value >> 8) & 0xFF));
                append(out, static_cast<uint8_t>(value & 0xFF));
            }
            else if (value <= 0xFFFFFFFFULL)
            {
                append(out, static_cast<uint8_t>(mt | 26));
                append(out, static_cast<uint8_t>((value >> 24) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 16) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 8) & 0xFF));
                append(out, static_cast<uint8_t>(value & 0xFF));
            }
            else
            {
                append(out, static_cast<uint8_t>(mt | 27));
                append(out, static_cast<uint8_t>((value >> 56) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 48) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 40) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 32) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 24) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 16) & 0xFF));
                append(out, static_cast<uint8_t>((value >> 8) & 0xFF));
                append(out, static_cast<uint8_t>(value & 0xFF));
            }

            return out.size() - before;
        }
    }

    template <typename ByteT>
    inline size_t encodeMapSize(std::vector<ByteT>& out, uint64_t mapSize)
    {
        return detail::encode_type_and_length(out, 5 /* map */, mapSize);
    }

    template <typename ByteT>
    inline size_t encodeUnsigned(std::vector<ByteT>& out, uint64_t value)
    {
        return detail::encode_type_and_length(out, 0 /* unsigned */, value);
    }

    template <typename ByteT>
    inline size_t encodeInteger(std::vector<ByteT>& out, int64_t value)
    {
        if (value >= 0)
        {
            return detail::encode_type_and_length(out, 0 /* unsigned */, static_cast<uint64_t>(value));
        }

        // CBOR negative integer encoding: -1 - n
        const uint64_t n = static_cast<uint64_t>(-(value + 1));
        return detail::encode_type_and_length(out, 1 /* negative */, n);
    }

    template <typename ByteT>
    inline size_t encodeBytes(std::vector<ByteT>& out, std::span<const ByteT> bytes)
    {
        const size_t before = out.size();
        (void)detail::encode_type_and_length(out, 2 /* bytes */, static_cast<uint64_t>(bytes.size()));
        out.insert(out.end(), bytes.begin(), bytes.end());
        return out.size() - before;
    }

    template <typename ByteT>
    inline size_t encodeText(std::vector<ByteT>& out, const std::string& text)
    {
        const size_t before = out.size();
        (void)detail::encode_type_and_length(out, 3 /* text */, static_cast<uint64_t>(text.size()));
        out.insert(out.end(), text.begin(), text.end());
        return out.size() - before;
    }

    template <typename ByteT>
    inline size_t encodeBool(std::vector<ByteT>& out, bool value)
    {
        const size_t before = out.size();
        // Major type 7 (simple/float), additional 20=false, 21=true
        detail::append(out, static_cast<uint8_t>((7u << 5) | (value ? 21u : 20u)));
        return out.size() - before;
    }
}
