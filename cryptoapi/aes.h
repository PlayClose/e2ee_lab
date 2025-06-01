#pragma once
#include <cassert>
#include "i_cipher.h"
#include "aes/aes.h"
#include "misc.h"

namespace playclose {
	namespace crypto {

	auto constexpr aes_data_size = 16;
	auto constexpr aes_key_size = 32;
	auto constexpr padding = ' ';
	
	struct aes : public i_cipher 
	{
		aes() = default;
		~aes() = default;

		std::string encrypt(const std::string& hexkey, const std::string& data,
								const std::string& iv = "", const std::string& aad = "") override {
			std::vector<uint8_t> key = parse_hex(hexkey);
			std::vector<uint8_t> buf(aes_data_size);
			std::vector<std::string> chunks;
			std::string res;	
			std::string _data = data;

			aligned_16bytes(_data);

 			for (int i = 0; i < _data.size(); i += aes_data_size) {
 				chunks.push_back(_data.substr(i, aes_data_size));
			}

			AES256Encrypt enc(key.data());
			
			for(auto& i : chunks) {
				enc.Encrypt(buf.data(), parse_hex(convert_data_to_hex(i)).data());
				res += convert_hex_to_data(parse_vector(buf));
			}

			return res; 
		}
			
		std::string decrypt(const std::string& hexkey, const std::string& data,
								const std::string& iv = "", const std::string& aad = "") override {
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
			remove_aligned_symbol(res);

			return res;
		}

		void aligned_16bytes(std::string& payload) {
			if(payload.empty()) {
				return;
			}
			if(!(payload.size() % 16)) {
				return;
			}
			else {
				int need_to_add = 16 - payload.size() % 16;
				for(auto i = 0; i < need_to_add; i++) {
					payload += padding;	
				}
				return;
			}
		}
		
		void remove_aligned_symbol(std::string& payload) {
			if(payload.empty()) {
					return;
			}
			for(auto i = 0; i < 16; i++) {
				if(payload.back() == padding) {
					payload.pop_back();
				}
				else {
					return;
				}
			}
		}
		
	};

} // namespace crypto
} // namespace playclose
