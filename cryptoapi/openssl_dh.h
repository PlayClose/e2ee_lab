#pragma once 
#include <string>
#include <memory>
#include <iostream>

#include <openssl/ssl.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

#include "i_key_negotiation.h"
#include "misc.h"

namespace playclose {
	namespace crypto {

	template <auto func>
	using deleter = std::integral_constant<decltype(func), func>;

	class openssl_dh : public i_key_negotiation
	{
	private:
		std::unique_ptr<BIGNUM, deleter<BN_free>> prime_;
		std::unique_ptr<BIGNUM, deleter<BN_free>> gen_;
		std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> key_pair_;

	public:	
		openssl_dh(size_t prime_len, int gen = 2) {
			prime_gen(prime_len, gen);
			generate_keys();
		}

		openssl_dh(const std::string& hex_prime, const std::string& hex_gen = "2") {
			prime_.reset(convert_hex_to_bn(hex_prime));	
			gen_.reset(convert_hex_to_bn(hex_gen));
			generate_keys();
		}
	
		void set_prime(const std::string& hex_prime, const std::string& hex_gen = "2") override {
			prime_.reset(convert_hex_to_bn(hex_prime));	
			gen_.reset(convert_hex_to_bn(hex_gen));
			generate_keys();
		}
		std::string get_prime() override {
			return convert_bn_to_hex(prime_.get());
		}
		std::string get_pub_key() override {
			return get_public_key();
		}
		std::string get_cipher_key(const std::string& cli_pub_key) override {
			return generate_secret_key(cli_pub_key);
		}
	private:
		std::string convert_bn_to_hex(const BIGNUM* bigNum);
		BIGNUM* convert_hex_to_bn(const std::string& hex);
		int prime_gen(int prime_len, int gen);
		int create_domain_parameter_key(std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>>& domain_param_key);
		int generate_keys();
		void generate_peer_public_key(const std::string& hex_public_key, std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>>& public_key);
		std::string get_public_key();
		std::string get_private_key();
		std::string generate_secret_key(const std::string& public_key);
	};

} // namespace crypto
} // namespace playclose
