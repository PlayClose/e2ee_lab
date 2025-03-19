#include "openssl_dh.h"
//TODO причесать код
namespace playclose {
	namespace crypto {

BIGNUM* openssl_dh::convert_hex_to_bn(const std::string& hex) {
	BIGNUM* bn = nullptr;
	if (!BN_hex2bn(&bn, hex.data())) {
		return nullptr;
	}
	return bn;
}

std::string openssl_dh::convert_bn_to_hex(const BIGNUM* bn) {
	char* tmp = BN_bn2hex(bn);
	if (!tmp) {
		return "";
	}
	std::string hex(tmp);
	OPENSSL_free(tmp);
	return hex;
}


int openssl_dh::prime_gen(int prime_len, int gen) {
	if (gen <= 1) {
		return EXIT_FAILURE; //TODO add std::error_code 
	}
	std::unique_ptr<BIGNUM, deleter<BN_free>> bigAdd{BN_new()};
	std::unique_ptr<BIGNUM, deleter<BN_free>> bigRem{BN_new()};
	if (!bigAdd || !bigRem) {
		return EXIT_FAILURE;
	}
	if (gen == DH_GENERATOR_2) {
		if (!BN_set_word(bigAdd.get(), 24) || !BN_set_word(bigRem.get(), 23)) {
			return EXIT_FAILURE;
		}
	}
	else {
		if (!BN_set_word(bigAdd.get(), 12) || !BN_set_word(bigRem.get(), 11)) {
			return EXIT_FAILURE;
		}
	}
	prime_.reset(BN_new());
	if (!prime_) {
		return EXIT_FAILURE;
	}
	gen_.reset(BN_new());
	if (!gen_) {
		return EXIT_FAILURE;
	}
	if (!BN_generate_prime_ex(prime_.get(), prime_len, 1,
		bigAdd.get(), bigRem.get(), nullptr)) {
		return EXIT_FAILURE;
	}
	if (!BN_set_word(gen_.get(), static_cast<BN_ULONG>(gen))) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int openssl_dh::create_domain_parameter_key(std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>>& domainParamKey)
{
	std::unique_ptr<OSSL_PARAM_BLD, deleter<OSSL_PARAM_BLD_free>> paramBuild{OSSL_PARAM_BLD_new()};
	if (!paramBuild) {
		return EXIT_FAILURE;
	}

	if (!OSSL_PARAM_BLD_push_BN(paramBuild.get(), OSSL_PKEY_PARAM_FFC_P, prime_.get()) ||
	!OSSL_PARAM_BLD_push_BN(paramBuild.get(), OSSL_PKEY_PARAM_FFC_G, gen_.get())) {
		return EXIT_FAILURE;
	}

	std::unique_ptr<OSSL_PARAM, deleter<OSSL_PARAM_free>>
	param{OSSL_PARAM_BLD_to_param(paramBuild.get())};
	if (!param) {
		return EXIT_FAILURE;
	}

	std::unique_ptr<EVP_PKEY_CTX, deleter<EVP_PKEY_CTX_free>>
	ctx{EVP_PKEY_CTX_new_from_name(nullptr, "DHX", nullptr)};
	if (!ctx) {
		return EXIT_FAILURE;
	}

	if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
		return EXIT_FAILURE;
	}

	EVP_PKEY* tmp = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &tmp,
	  EVP_PKEY_KEY_PARAMETERS, param.get()) <= 0) {
		return EXIT_FAILURE;
	}

	domainParamKey.reset(tmp);

	return EXIT_SUCCESS;
}

int openssl_dh::generate_keys() {

  	std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> domainParamKey;
  	int result = create_domain_parameter_key(domainParamKey);
	if (result) {
		return result;
  	}

  	std::unique_ptr<EVP_PKEY_CTX, deleter<EVP_PKEY_CTX_free>> ctx{EVP_PKEY_CTX_new_from_pkey(nullptr, domainParamKey.get(), nullptr)};

	if (!ctx) {
		return EXIT_FAILURE;
	}

	if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
		return EXIT_FAILURE;
	}

	EVP_PKEY* keyPair = nullptr;
	if (EVP_PKEY_generate(ctx.get(), &keyPair) <= 0) {
		return EXIT_FAILURE;
	}

	key_pair_.reset(keyPair);

	return EXIT_SUCCESS;
}

std::string openssl_dh::get_private_key() {

	BIGNUM* key = nullptr;
	if (!EVP_PKEY_get_bn_param(key_pair_.get(), OSSL_PKEY_PARAM_PRIV_KEY, &key)) {
		return "";
	}
	std::unique_ptr<BIGNUM, deleter<BN_free>> privateKeyHolder{key};
	return convert_bn_to_hex(key);
}

std::string openssl_dh::get_public_key() {

	BIGNUM* key = nullptr;
	if (!EVP_PKEY_get_bn_param(key_pair_.get(), OSSL_PKEY_PARAM_PUB_KEY, &key)) {
		return "";
	}
	std::unique_ptr<BIGNUM, deleter<BN_free>> publicKeyHolder{key};
	return convert_bn_to_hex(key);
}

void openssl_dh::generate_peer_public_key(const std::string& hex_public_key, std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>>& public_key) {

	std::unique_ptr<BIGNUM, deleter<BN_free>> bn_public_key{convert_hex_to_bn(hex_public_key)};
	if (!bn_public_key) {
		return;
	}

	std::unique_ptr<OSSL_PARAM_BLD, deleter<OSSL_PARAM_BLD_free>> param_bld{OSSL_PARAM_BLD_new()};
	if (!param_bld) {
		return;
	}

	if (!OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_PUB_KEY, bn_public_key.get())) {
		return;
	}

	if (!OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_FFC_P, prime_.get()) ||
	  	!OSSL_PARAM_BLD_push_BN(param_bld.get(), OSSL_PKEY_PARAM_FFC_G, gen_.get())) {
		return;
	}

	std::unique_ptr<OSSL_PARAM, deleter<OSSL_PARAM_free>> param{OSSL_PARAM_BLD_to_param(param_bld.get())};
	if (!param) {
		return;
	}

	std::unique_ptr<EVP_PKEY_CTX, deleter<EVP_PKEY_CTX_free>> ctx{EVP_PKEY_CTX_new_from_name(nullptr, "DHX", nullptr)};
	if (!ctx) {
		return;
	}

	if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
		return;
	}

	EVP_PKEY* tmp = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &tmp, EVP_PKEY_PUBLIC_KEY, param.get()) <= 0) {
		return;
	}

	public_key.reset(tmp);
}

std::string openssl_dh::generate_secret_key(const std::string& public_key) {

	std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> peer_public_key;
	generate_peer_public_key(public_key, peer_public_key);
	std::unique_ptr<EVP_PKEY_CTX, deleter<EVP_PKEY_CTX_free>> ctx{EVP_PKEY_CTX_new(key_pair_.get(), nullptr)};
	if (!ctx) {
		return "";
	}
	if (EVP_PKEY_derive_init(ctx.get()) <= 0) {
		return "";
	}
	if (EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key.get()) <= 0) {
		return "";
	}
	size_t len = 0;
	if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0) {
		return "";
	}
	if (len == 0) {
		return "";
	}
	std::string secret_key;
	secret_key.resize(len);
	if (EVP_PKEY_derive(ctx.get(), static_cast<unsigned char*>(static_cast<void*>(&secret_key.front())), &len) <= 0) {
		return "";
	}

  	return convert_data_to_hex(secret_key);
}

} // namespace crypto
} // namespace playclose
