#pragma once 

namespace playclose {
	namespace crypto {

	enum class cipher : uint8_t
	{
		kuznechik,
		aes
	};

	struct i_cipher
	{
		i_cipher() = default;
		~i_cipher() = default;
		virtual std::string encrypt(const std::string& key, const std::string& data) = 0;
		virtual std::string decrypt(const std::string& key, const std::string& data) = 0;
	};
	
} // namespace crypto
} // namespace playclose
