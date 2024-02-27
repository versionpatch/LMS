#ifndef _UTILS_H
#define _UTILS_H

#include <iostream>
#include <vector>
#include <array>
#include <gmpxx.h>
#include <type_traits>
#include <charconv>

#include "sha256.h"

static constexpr auto n = size_t(32);
static constexpr auto m = size_t(32);
static constexpr auto h = size_t(5);
static constexpr auto w = size_t(4);
static constexpr auto p = size_t(67);
static constexpr auto ls = size_t(4);
static constexpr auto typecode = uint32_t(3);
static constexpr auto d_pblc = uint16_t(0x8080);
static constexpr auto d_mesg = uint16_t(0x8181);
static constexpr auto d_leaf = uint16_t(0x8282);
static constexpr auto d_intr = uint16_t(0x8383);
static constexpr auto lms_typecode = uint32_t(5);

using byte_string_n = std::array<uint8_t, n>;
using hash_array_p = std::array<byte_string_n, p>;
using pkey_array_h = std::array<hash_array_p, 1 << h>;
using hash_tree_h = std::array<byte_string_n, (1 << (h+1)) - 1>;

template <typename T>
uint8_t coef(const T &data, int i)
{
    return ((1 << w) - 1) & (data[(i * w) / 8] >> (8 - (w * (i % (8 / w)) + w)));
}

uint32_t checksum(std::array<uint8_t, n> s)
{
    auto sum = uint32_t(0);
    for (uint32_t i = 0;i < (n * 8 / w);i++)
        sum += ((1 << w) - 1) - coef(s, i);
    return (sum << ls);
}



namespace utils
{

    static auto sha256 = SHA256(); 


    inline void advance_hashes(hash_array_p &hashes,
                               const std::array<uint8_t, p> &from,
                               const std::array<uint8_t, p> &to,
                               const std::array<uint8_t, 16> &I,
                               const uint32_t q)
    {
        sha256.reset();
        std::array<uint8_t, sizeof(q)> q_bytes;
        for (size_t i = 0;i < sizeof(uint32_t);i++)
            q_bytes[i] = (q >> (8 * (sizeof(uint32_t) - 1 - i))) & 0xFF;
        for (uint16_t i = 0;i < p;i++)
        {
            for (uint8_t j = from[i];j < to[i];j++)
            {
                sha256.add(I.data(), sizeof(I)/sizeof(I[0]));
                sha256.add(q_bytes.data(), sizeof(q));
                sha256.add(&i, sizeof(i));
                sha256.add(&j, sizeof(j));
                sha256.add(hashes[i].data(), n);
                sha256.getHash(hashes[i].data());
                sha256.reset();
            }
        }
    }

    inline byte_string_n public_hash(const hash_array_p &hashes,
                                     const std::array<uint8_t, 16> &I,
                                     const uint32_t q)
    {
        std::array<uint8_t, sizeof(q)> q_bytes;
        for (size_t i = 0;i < sizeof(uint32_t);i++)
            q_bytes[i] = (q >> (8 * (sizeof(uint32_t) - 1 - i))) & 0xFF;
        sha256.reset();
        sha256.add(I.data(), sizeof(I)/sizeof(I[0]));
        sha256.add(q_bytes.data(), sizeof(q));
        sha256.add(&d_pblc, sizeof(d_pblc));
        for (size_t i = 0;i < p;i++)
            sha256.add(hashes[i].data(), n);
        auto output_hash = byte_string_n();
        sha256.getHash(output_hash.data());
        sha256.reset();
        return output_hash;
    }

    inline byte_string_n message_hash(std::ifstream &message_file,
                                      const byte_string_n &c,
                                      const std::array<uint8_t, 16> &I,
                                      const uint32_t q)
    {
        sha256.reset();
        std::array<uint8_t, sizeof(q)> q_bytes;
        for (size_t i = 0;i < sizeof(uint32_t);i++)
            q_bytes[i] = (q >> (8 * (sizeof(uint32_t) - 1 - i))) & 0xFF;

        sha256.add(I.data(), sizeof(I)/sizeof(I[0]));
        sha256.add(q_bytes.data(), sizeof(q));
        sha256.add(&d_mesg, sizeof(d_mesg));
        sha256.add(c.data(), n);
        {
            auto byte = char(0);
            while (message_file)
            {
                message_file.read(&byte, 1);
                if (!message_file.eof())
                {
                    sha256.add(&byte, 1);
                }
            }
        }   
        auto q_hash = byte_string_n();
        sha256.getHash(q_hash.data());
        sha256.reset();
        return q_hash;
    }

    inline byte_string_n leaf_hash(const byte_string_n &pub_key,
                                   const uint32_t r,
                                   const std::array<uint8_t, 16> &I)
    {
        sha256.reset();
        std::array<uint8_t, sizeof(r)> r_bytes;
        for (size_t i = 0;i < sizeof(uint32_t);i++)
            r_bytes[i] = (r >> (8 * (sizeof(uint32_t) - 1 - i))) & 0xFF;
        sha256.add(I.data(), sizeof(I)/sizeof(I[0]));
        sha256.add(r_bytes.data(), sizeof(r));
        sha256.add(&d_leaf, sizeof(d_leaf));
        sha256.add(pub_key.data(), n);
        auto output = byte_string_n();
        sha256.getHash(output.data());
        sha256.reset();
        return output;
    }
    inline byte_string_n node_hash(const byte_string_n &left,
                                   const byte_string_n &right,
                                   const uint32_t r,
                                   const std::array<uint8_t, 16> &I)
    {
        sha256.reset();
        std::array<uint8_t, sizeof(r)> r_bytes;
        for (size_t i = 0;i < sizeof(uint32_t);i++)
            r_bytes[i] = (r >> (8 * (sizeof(uint32_t) - 1 - i))) & 0xFF;
        sha256.add(I.data(), sizeof(I)/sizeof(I[0]));
        sha256.add(r_bytes.data(), sizeof(r));
        sha256.add(&d_intr, sizeof(d_intr));
        sha256.add(left.data(), n);
        sha256.add(right.data(), n);
        auto output = byte_string_n();
        sha256.getHash(output.data());
        sha256.reset();
        return output;
    }

    //Utility for reading binary files into byte arrays and uint32_t
    template <typename... Args>
    size_t stream_to_bytes([[maybe_unused]] std::istream &istream)
    {
        return 0;
    }
    template <size_t size, typename... Args>
    size_t stream_to_bytes(std::istream &istream, std::array<uint8_t, size> &arr, Args&... args);
    template <typename... Args>
    size_t stream_to_bytes(std::istream &istream, uint32_t &v, Args&... args);

    template <size_t size, typename... Args>
    size_t stream_to_bytes(std::istream &istream, std::array<uint8_t, size> &arr, Args&... args)
    {
        static_assert(size > 0);
        auto counter = size_t(0);
        auto byte = char(0);
        while (istream)
        {
            istream.read(&byte, 1);
            if (!istream.eof())
            {
                arr[counter++] = static_cast<uint8_t>(byte);
                if (counter == size)
                    break;
            }
            else
            {
                return counter;
            }
        }
        return stream_to_bytes(istream, args...) + counter;
    }
    template <typename... Args>
    size_t stream_to_bytes(std::istream &istream, uint32_t &v, Args&... args)
    {
        auto byte = char(0);
        auto count = size_t(0);
        v = 0;
        if (istream)
        {
            for (count = 0;count < 4;count++)
            {
                istream.read(&byte, 1);
                if (!istream.eof())
                    v |= (static_cast<uint8_t>(byte)) << 8*(sizeof(uint32_t) - 1 - count);
                else
                    break;
            }
        }
        if (count < 4)
            return count;
        return stream_to_bytes(istream, args...) + count;
    }
    
    //Utility for reading hex strings into byte arrays and uint32_t
    template<typename... Args>
    size_t hex_to_bytes([[maybe_unused]] std::string_view str)
    {
        return 0;
    }
    template <size_t size, typename... Args>
    size_t hex_to_bytes(std::string_view str, std::array<uint8_t, size> &arr, Args&... args);
    template <typename... Args>
    size_t hex_to_bytes(std::string_view str, uint32_t &v, Args&... args);

    template <size_t size, typename... Args>
    size_t hex_to_bytes(std::string_view str, std::array<uint8_t, size> &arr, Args&... args)
    {
        const auto max_counter = [&] {if (size*2 <= str.size()) return size; return str.size()/2; }();
        for (size_t i = 0;i < max_counter;i++)
        {
            auto sstr = str.substr(i * 2, 2);
            auto [ptr, ec] = std::from_chars(sstr.data(), sstr.data() + 2, arr[i], 16);
            if (ec != std::errc())
                return i;
        }
        if (max_counter < size)
            return max_counter;
        return size + hex_to_bytes(str.substr(max_counter*2), args...); 
    }
    template <typename... Args>
    size_t hex_to_bytes(std::string_view str, uint32_t &v, Args&... args)
    {
        if (str.size() < sizeof(uint32_t) * 2)
            return 0;
        v = 0;
        auto temp = uint32_t(0);
        for (size_t i = 0;i < sizeof(uint32_t);i++)
        {
            auto sstr = str.substr(i * 2, 2);
            auto [ptr, ec] = std::from_chars(sstr.data(), sstr.data() + 2, temp, 16);
            if (ec != std::errc())
                return 0;
            v |= (temp << 8*(sizeof(uint32_t) - 1 -i));
        }
        return sizeof(uint32_t) + hex_to_bytes(str.substr(sizeof(uint32_t)*2), args...);
    }

    //Utility for printing hex strings
    template <typename T, typename std::enable_if_t<std::is_integral<T>::value>* = nullptr>
    void print_hex(std::ostream &ostream, T byte)
    {
        auto byte_array = reinterpret_cast<uint8_t*>(&byte);
        for (int i = static_cast<int>(sizeof(T)) - 1;i >= 0;i--)
        {
            ostream << std::setw(2) << std::setfill('0') << static_cast<uint64_t>(byte_array[i]);
        }
    }

    template <typename T, typename V = typename T::value_type,
              typename std::enable_if_t<std::is_integral<V>::value>* = nullptr>
    void print_hex(std::ostream &ostream, T &byte_array)
    {
        std::for_each(byte_array.cbegin(), byte_array.cend(), [&](V v)
        {
            print_hex(ostream, v);
        });
    }

    //Utility for writing byte strings
    template <typename T, typename std::enable_if_t<std::is_integral<T>::value>* = nullptr>
    void print_bytes(std::ostream &ostream, T byte)
    {
        auto byte_array = reinterpret_cast<uint8_t*>(&byte);
        for (int i = static_cast<int>(sizeof(T)) - 1;i >= 0;i--)
        {
            ostream << byte_array[i];
        }
    }

    template <typename T, typename V = typename T::value_type,
              typename std::enable_if_t<std::is_integral<V>::value>* = nullptr>
    void print_bytes(std::ostream &ostream, T &byte_array)
    {
        std::for_each(byte_array.cbegin(), byte_array.cend(), [&](V v)
        {
            print_bytes(ostream, v);
        });
    }
}


#endif