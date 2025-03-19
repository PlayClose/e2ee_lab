#include <iostream>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

#include "crypto_api.h"

int main() {
	//Запускается только на сервере для получения p/g.
	auto srv = playclose::crypto::get_api<playclose::crypto::openssl_dh, playclose::crypto::aes>(512, 2);
	std::cout << "srv::get_pub_key():           " << srv->get_pub_key().length() << std::endl;
	std::string enc = srv->encrypt(srv->get_pub_key(), "aaaaaaaaaaaaaaaa");
	std::cout << "enc: " << enc << std::endl;
	std::string dec = srv->decrypt(srv->get_pub_key(), enc);
	std::cout << "dec: " << dec << std::endl;
	
	
	return EXIT_SUCCESS;
}
