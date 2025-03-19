#pragma once
#include "i_cipher.h"

namespace playclose {
	namespace crypto {

	struct kuznechik : public i_cipher 
	{
		kuznechik() {
			std::cout << "kuznechik::ctor()" << std::endl;
		}
		std::string encrypt(const std::string& key, const std::string& data) override {
			std::cout << __FUNCTION__ <<"size: " << key.length()/2 << " key: " << key << std::endl;
			return "";
		}
		std::string decrypt(const std::string& key, const std::string& data) override {
			std::cout << __FUNCTION__ <<"size: " << key.length()/2 << " key: " << key << std::endl;
			return "";
		}
	};

} // namespace crypto
} // namespace playclose
