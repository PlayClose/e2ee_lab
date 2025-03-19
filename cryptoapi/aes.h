#pragma once
#include <cassert>
#include "i_cipher.h"
#include "aes/aes.h"
#include "misc.h"

namespace playclose {
	namespace crypto {

	auto constexpr aes_data_size = 16;
	auto constexpr aes_key_size = 32;
	
	struct aes : public i_cipher 
	{
		aes() = default;
		~aes() = default;

		std::string encrypt(const std::string& hexkey, const std::string& data) override {
			std::vector<uint8_t> key = parse_hex(hexkey);
			std::vector<uint8_t> buf(aes_data_size);
			std::vector<std::string> chunks;
			std::string res;	

 			for (int i = 0; i < data.size(); i += aes_data_size) {
 				chunks.push_back(data.substr(i, aes_data_size));
			}

			AES256Encrypt enc(key.data());
			
			for(auto& i : chunks) {
				enc.Encrypt(buf.data(), parse_hex(convert_data_to_hex(i)).data());
				res += convert_hex_to_data(parse_vector(buf));
			}

			return res; 
		}
			
		std::string decrypt(const std::string& hexkey, const std::string& data) override {
			std::vector<uint8_t> buf(aes_data_size);
			std::vector<uint8_t> key = parse_hex(hexkey);
			std::vector<std::string> chunks;
			std::string res;	
 			for (int i = 0; i < data.size(); i += aes_data_size) {
 				chunks.push_back(data.substr(i, aes_data_size));
			}

			AES256Decrypt dec(key.data());
			for(auto& i : chunks) {
				dec.Decrypt(buf.data(), parse_hex(convert_data_to_hex(i)).data());
				res += convert_hex_to_data(parse_vector(buf));
			}

			return res;
		}
		
	};

} // namespace crypto
} // namespace playclose
