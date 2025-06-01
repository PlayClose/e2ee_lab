#include <iostream>
#include <memory>

#include <openssl/ssl.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

//#include "aes.h"
#include "aesgcm.h"

using namespace playclose::crypto;

int main() {
	
	const std::string key = "2D0E9B8CD769753E5AF7878886484CF170F2C46194A217175487CE1EBF71C40B07808CC619E77A0908A3007EEE5FB0FA1F13E4A03787B1818ABC8A2356469B95";
	const std::string plaintext = "hello";

	aesgcm obj;			
	std::string enc = obj.encrypt(key, plaintext);
	std::string dec = obj.decrypt(key, enc);	

	std::cout << "enc:" << std::endl;
	std::cout << enc << std::endl;
	std::cout << "dec:" << std::endl;
	std::cout << dec << std::endl;

	if(dec == plaintext) 
		std::cout << "SUCCESS" << std::endl;
		
	return EXIT_SUCCESS;
}
