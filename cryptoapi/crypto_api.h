#pragma once 
#include "openssl_dh.h"
#include "aes.h"

namespace playclose {
	namespace crypto {

	//TODO SFINAE is cipher based from i_cipher and so on
	//is key_negotiation from base_key_negotiation
	template <typename key_negotiation, typename cipher>
	class key_bank
	{
	private:
		std::unique_ptr<i_cipher> cipher_;
		std::unique_ptr<i_key_negotiation> key_negotiation_;
	public:
		template<typename ... Args>
		key_bank(Args... args) : 
			key_negotiation_(std::make_unique<key_negotiation>(args...))
			,cipher_(std::make_unique<cipher>())
		{
		}	
		std::string encrypt(const std::string& cli_pub_key, const std::string& data) {
			return cipher_->encrypt(key_negotiation_->get_cipher_key(cli_pub_key), data);
		}
		std::string decrypt(const std::string& cli_pub_key, const std::string& data) {
			return cipher_->decrypt(key_negotiation_->get_cipher_key(cli_pub_key), data);
		}
		std::string get_prime() {
			return key_negotiation_->get_prime();
		}
		std::string get_pub_key() {
			return key_negotiation_->get_pub_key();
		}
	};		
	
	template <typename Proto, typename Cipher, typename ... Args, std::enable_if_t<(sizeof...(Args) <= 2)>* = nullptr>
 	std::shared_ptr<key_bank<Proto, Cipher>> get_api(Args... args) {
 		return std::make_shared<key_bank<Proto, Cipher>>(args...);
 	}

} // namespace crypto
} // namespace playclose
