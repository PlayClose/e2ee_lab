#pragma once
#include <cassert>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "i_cipher.h"
#include "misc.h"

namespace playclose {
	namespace crypto {

	/* Unique initialisation vector */
	static const unsigned char gcm_iv[] = {
		0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
	};

	/*
	 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
	 * which can be authenticated using the generated Tag value.
	 */
	static const unsigned char gcm_aad[] = {
		0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
		0x7f, 0xec, 0x78, 0xde
	};

	template <auto func>
		using deleter = std::integral_constant<decltype(func), func>;

	static OSSL_LIB_CTX *libctx = NULL;
	static const char *propq = NULL;

	struct aesgcm : public i_cipher 
	{
		std::unique_ptr<EVP_CIPHER_CTX, deleter<EVP_CIPHER_CTX_free>> ctx;
		std::unique_ptr<EVP_CIPHER, deleter<EVP_CIPHER_free>> cipher;

		aesgcm() {
			
			ctx.reset(EVP_CIPHER_CTX_new());
			/* Create a context for the encrypt operation */
			if ((ctx == nullptr))
				throw std::runtime_error("ctx initialization error");	

			cipher.reset(EVP_CIPHER_fetch(libctx, "AES-256-GCM", propq));
			/* Fetch the cipher implementation */
			if ((cipher == nullptr))
				throw std::runtime_error("cipher initialization error");
		}

		~aesgcm() = default;

		std::string encrypt(const std::string& hexkey, const std::string& data) override {
			std::cout << "hexkey: " << hexkey  << " " << hexkey.size()<< std::endl;	
			std::vector<uint8_t> key = parse_hex(hexkey);
			auto plain = parse_hex(convert_data_to_hex(data));

			int outlen, tmplen;
			size_t gcm_ivlen = sizeof(gcm_iv);
			unsigned char outbuf[1024];
			unsigned char outtag[16];
			OSSL_PARAM params[2] = {
				OSSL_PARAM_END, OSSL_PARAM_END
			};

			/* Set IV length if default 96 bits is not appropriate */
			params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
													&gcm_ivlen);

			/*
			 * Initialise an encrypt operation with the cipher/mode, key, IV and
			 * IV length parameter.
			 * For demonstration purposes the IV is being set here. In a compliant
			 * application the IV would be generated internally so the iv passed in
			 * would be NULL.
			 */
			if (!EVP_EncryptInit_ex2(ctx.get(), cipher.get(), key.data(), gcm_iv, params))
				throw std::runtime_error("initialization error"); //TODO change exception message

			/* Zero or more calls to specify any AAD */
			if (!EVP_EncryptUpdate(ctx.get(), NULL, &outlen, gcm_aad, sizeof(gcm_aad)))
				throw std::runtime_error("initialization error");

			/* Encrypt plaintext */
			if (!EVP_EncryptUpdate(ctx.get(), outbuf, &outlen, plain.data(), plain.size()))
				throw std::runtime_error("initialization error");

			/* Finalise: note get no output for GCM */
			if (!EVP_EncryptFinal_ex(ctx.get(), outbuf, &tmplen))
				throw std::runtime_error("initialization error");

			/* Get tag */
			params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
														  outtag, 16);

			if (!EVP_CIPHER_CTX_get_params(ctx.get(), params))
				throw std::runtime_error("initialization error");

			std::vector<uint8_t> buf_outtag(outtag, outtag + 16);
			std::vector<uint8_t> buf(outbuf, outbuf + outlen);
			return convert_hex_to_data(parse_vector(buf)) + convert_hex_to_data(parse_vector(buf_outtag));
		}
			
		std::string decrypt(const std::string& hexkey, const std::string& data) override {
			auto tag = parse_hex(convert_data_to_hex(data.substr(data.size() - 16, 16)));
			auto cypher = parse_hex(convert_data_to_hex(data.substr(0, data.size() - 16)));
			std::vector<uint8_t> key = parse_hex(hexkey);

			int outlen, rv;
			size_t gcm_ivlen = sizeof(gcm_iv);
			unsigned char outbuf[1024];
			OSSL_PARAM params[2] = {
				OSSL_PARAM_END, OSSL_PARAM_END
			};

			/* Set IV length if default 96 bits is not appropriate */
			params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
													&gcm_ivlen);

			/*
			 * Initialise an encrypt operation with the cipher/mode, key, IV and
			 * IV length parameter.
			 */
			if (!EVP_DecryptInit_ex2(ctx.get(), cipher.get(), key.data(), gcm_iv, params))
				throw std::runtime_error("initialization error");

			/* Zero or more calls to specify any AAD */
			if (!EVP_DecryptUpdate(ctx.get(), NULL, &outlen, gcm_aad, sizeof(gcm_aad)))
				throw std::runtime_error("initialization error");

			/* Decrypt plaintext */
			if (!EVP_DecryptUpdate(ctx.get(), outbuf, &outlen, cypher.data(), cypher.size()))
				throw std::runtime_error("initialization error");

			/* Set expected tag value. */
			params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
														  (void*)tag.data(), tag.size());

			if (!EVP_CIPHER_CTX_set_params(ctx.get(), params))
				throw std::runtime_error("initialization error");

			std::vector<uint8_t> buf(outbuf, outbuf + outlen);

			/* Finalise: note get no output for GCM */
			rv = EVP_DecryptFinal_ex(ctx.get(), outbuf, &outlen);
			/*
			 * Print out return value. If this is not successful authentication
			 * failed and plaintext is not trustworthy.
			 */
			//printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");
			if(!(rv > 0)) 
				std::runtime_error("tag is different!");

			return convert_hex_to_data(parse_vector(buf));
		}
	};

} // namespace crypto
} // namespace playclose
