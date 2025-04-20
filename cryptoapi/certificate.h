#include <memory>
#include <string>
#include <vector>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

namespace playclose {
	namespace crypto {

	template <auto func>
		using deleter = std::integral_constant<decltype(func), func>;

	/*enum class sert_type : uint8_t { //TODO doubt the need
		x509,
		pgp,
	}*/
	
	class x509_certificate
	{
		std::unique_ptr<X509, deleter<X509_free>> ca_cert_;
		std::unique_ptr<X509_REQ, deleter<X509_REQ_free>> csr_cert_;
		std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> key_pair_;
	public:
		x509_certificate() : 
			ca_cert_{nullptr},
			csr_cert_{nullptr},
			key_pair_{generate_rsa_keypair()}
		{
		}
		~x509_certificate() = default;
	private:
		std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> generate_rsa_keypair(int key_bits = 2048);
		std::string x509_to_pem();
		std::string x509req_to_pem();
		std::unique_ptr<X509_REQ, deleter<X509_REQ_free>> pem_to_x509req(const std::string& pem_data);
		std::unique_ptr<X509, deleter<X509_free>> pem_to_x509(const std::string& pem_data);
		std::unique_ptr<X509, deleter<X509_free>> generate_x509();
		std::unique_ptr<X509, deleter<X509_free>> sign_csr(X509_REQ* req, int daysValid = 365);
		std::unique_ptr<X509, deleter<X509_free>> create_self_signed_cert(const std::string& common_name = "server", int valid_days = 365);
	};

	} //namespace crypto 
} //namespace playclose
