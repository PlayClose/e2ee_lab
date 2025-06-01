#pragma once 

namespace playclose {
	namespace crypto {

	enum class cipher : uint8_t
	{
		kuznechik,
		aes,
		aesgcm
	};

	struct i_cipher
	{
		i_cipher() = default;
		virtual ~i_cipher() = default;
		virtual std::string encrypt(const std::string& key, const std::string& data,
									[[maybe_unused]] const std::string& iv = "", [[maybe_unused]] const std::string& aad = "") = 0;
		virtual std::string decrypt(const std::string& key, const std::string& data,
									[[maybe_unused]] const std::string& iv = "", [[maybe_unused]] const std::string& aad = "") = 0;
	};
	
} // namespace crypto
} // namespace playclose
