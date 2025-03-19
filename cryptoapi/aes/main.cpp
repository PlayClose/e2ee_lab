#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <cassert>
#include <iomanip>
#include "aes.h"

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

signed char HexDigit(char c) {
    return p_util_hexdigit[(unsigned char)c];
}

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
        auto c1 = HexDigit(*(it++));
        if (it == str.end()) return std::nullopt;
        auto c2 = HexDigit(*(it++));
        if (c1 < 0 || c2 < 0) return std::nullopt;
        vch.push_back(Byte(c1 << 4) | Byte(c2));
    }
    return vch;
}

/** Parse the hex string into bytes (uint8_t or std::byte). Ignores whitespace. Returns nullopt on invalid input. */
template <typename Byte = std::byte>std::optional<std::vector<Byte>> TryParseHex(std::string_view str);             
/** Like TryParseHex, but returns an empty vector on invalid input. */
template <typename Byte = uint8_t>
std::vector<Byte> ParseHex(std::string_view hex_str) {
    return TryParseHex<Byte>(hex_str).value_or(std::vector<Byte>{});
}


constexpr std::array<ByteAsHex, 256> CreateByteToHexMap()
{
    constexpr char hexmap[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::array<ByteAsHex, 256> byte_to_hex{};
    for (size_t i = 0; i < byte_to_hex.size(); ++i) {
        byte_to_hex[i][0] = hexmap[i >> 4];
        byte_to_hex[i][1] = hexmap[i & 15];
    }
    return byte_to_hex;
}

} // namespace

std::string HexStr(const Span<const uint8_t> s)
{
    std::string rv(s.size() * 2, '\0');
    static constexpr auto byte_to_hex = CreateByteToHexMap();
    static_assert(sizeof(byte_to_hex) == 512);

    char* it = rv.data();
    for (uint8_t v : s) {
        std::memcpy(it, byte_to_hex[v].data(), 2);
        it += 2;
    }

    assert(it == rv.data() + rv.size());
    return rv;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------//


void TestAES256(const std::string &hexkey, const std::string &hexin)
{
    std::vector<uint8_t> key = ParseHex(hexkey);
    std::vector<uint8_t> in = ParseHex(hexin);
    std::vector<uint8_t> buf;

    //assert(key.size() == 32);
    //assert(in.size() == 16);
    AES256Encrypt enc(key.data());
    buf.resize(hexin.size()/2);
    enc.Encrypt(buf.data(), in.data());
	std::cout << "encrypt" << std::endl;
	for(auto i : buf) {
		std::cout << std::hex << std::setw(2) << static_cast<int>(i);
	}
	std::cout << std::endl;

    AES256Decrypt dec(key.data());
    dec.Decrypt(buf.data(), buf.data());
	std::cout << "decrypt" << std::endl;
	for(auto i : buf) {
		std::cout << std::hex << std::setw(2) << static_cast<int>(i);
	}
	std::cout << std::endl;

    if(buf == in);
		std::cout << "PASSED" << std::endl;
}

void TestAES256CBC(const std::string &hexkey, const std::string &hexiv, bool pad, const std::string &hexin, const std::string &hexout)
{
    std::vector<unsigned char> key = ParseHex(hexkey);
    std::vector<unsigned char> iv = ParseHex(hexiv);
    std::vector<unsigned char> in = ParseHex(hexin);
    std::vector<unsigned char> correctout = ParseHex(hexout);
    std::vector<unsigned char> realout(in.size() + AES_BLOCKSIZE);

    // Encrypt the plaintext and verify that it equals the cipher
    AES256CBCEncrypt enc(key.data(), iv.data(), pad);
    int size = enc.Encrypt(in.data(), in.size(), realout.data());
    realout.resize(size);
    //BOOST_CHECK(realout.size() == correctout.size());
    //BOOST_CHECK_MESSAGE(REALOUT == correctout, HexStr(realout) + std::string(" != ") + hexout);

    // Decrypt the cipher and verify that it equals the plaintext
    std::vector<unsigned char> decrypted(correctout.size());
    AES256CBCDecrypt dec(key.data(), iv.data(), pad);
    size = dec.Decrypt(correctout.data(), correctout.size(), decrypted.data());
    decrypted.resize(size);
    //BOOST_CHECK(decrypted.size() == in.size());
    //BOOST_CHECK_MESSAGE(decrypted == in, HexStr(decrypted) + std::string(" != ") + hexin);

    // Encrypt and re-decrypt substrings of the plaintext and verify that they equal each-other
    for(std::vector<unsigned char>::iterator i(in.begin()); i != in.end(); ++i)
    {
        std::vector<unsigned char> sub(i, in.end());
        std::vector<unsigned char> subout(sub.size() + AES_BLOCKSIZE);
        int _size = enc.Encrypt(sub.data(), sub.size(), subout.data());
        if (_size != 0)
        {
            subout.resize(_size);
            std::vector<unsigned char> subdecrypted(subout.size());
            _size = dec.Decrypt(subout.data(), subout.size(), subdecrypted.data());
            subdecrypted.resize(_size);
            //BOOST_CHECK(decrypted.size() == in.size());
            //BOOST_CHECK_MESSAGE(subdecrypted == sub, HexStr(subdecrypted) + std::string(" != ") + HexStr(sub));
        }
    }
}


int main() {
	
	TestAES256("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a");
	TestAES256("BB1003D77CDD8699A30A6E06ED84FF8B6B8090B0887946F7EEC6ABB1BEAF906589797C7E77447D48584AEFC865522C21127F805C27155196335E42F0DAF332C7", "6bc1bee22e409f96e93d7e117393172a6bc1bee22e409f96e93d7e117393172a");
	
	TestAES256CBC("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                  "000102030405060708090A0B0C0D0E0F", true, "6bc1bee22e409f96e93d7e117393172a",
                  "f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0");
	
	return EXIT_SUCCESS;
}
