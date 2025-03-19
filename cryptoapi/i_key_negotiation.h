#pragma once 

namespace playclose {
	namespace crypto {

	enum class negotiation_protocol : uint8_t 
	{
		deffie_hellman,
	};
	
	struct i_key_negotiation 
	{
		i_key_negotiation() = default;
		~i_key_negotiation() = default;
		virtual std::string get_prime() = 0;
		virtual std::string get_pub_key() = 0;
		virtual std::string get_cipher_key(const std::string& ) = 0;
	};

} // namespace crypto
} // namespace playclose
