#pragma once
#include <string>
#include <optional>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <ios>
#include <iomanip>

signed char hex_digit(char c);
std::string convert_data_to_hex(const std::string& data);
std::string convert_hex_to_data(const std::string& hex);
std::string parse_vector(const std::vector<uint8_t> buf);

const signed char p_util_hexdigit[256] =                                        
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,                                
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,                                
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,                               
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,                                
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };



constexpr inline bool IsSpace(char c) noexcept {
	return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}

template <typename Byte>
std::optional<std::vector<Byte>> TryParseHex(std::string_view str)
{
    std::vector<Byte> vch;
    vch.reserve(str.size() / 2); // two hex characters form a single byte

    auto it = str.begin();
    while (it != str.end()) {
        if (IsSpace(*it)) {
            ++it;
            continue;
        }
        auto c1 = hex_digit(*(it++));
        if (it == str.end()) return std::nullopt;
        auto c2 = hex_digit(*(it++));
        if (c1 < 0 || c2 < 0) return std::nullopt;
        vch.push_back(Byte(c1 << 4) | Byte(c2));
    }
    return vch;
}

template <typename Byte = std::byte>std::optional<std::vector<Byte>> TryParseHex(std::string_view str);             
template <typename Byte = uint8_t>
std::vector<Byte> parse_hex(std::string_view hex_str) {
    return TryParseHex<Byte>(hex_str).value_or(std::vector<Byte>{});
}
