#pragma once 
#include "openssl_dh.h"
#include "aes.h"
#include "certificate.h"

namespace playclose {
	namespace crypto {

	//Policy tags:
	struct ServerPolicy
	{};
	struct ClientPolicy
	{};
	
	//Forward declaratoin:
	template <typename key_negotiation, typename cipher>
	class server_certificate;
	
	template <typename key_negotiation, typename cipher>
	class client_certificate;

	//api
	template <typename certificate, typename key_negotiation, typename cipher
		,typename = typename std::enable_if<
			std::is_base_of<i_cipher, cipher>::value &&
			std::is_base_of<i_key_negotiation, key_negotiation>::value,
			void
		>::type
	>
	class api 
	{
	private:
		std::unique_ptr<i_cipher> cipher_;
		std::unique_ptr<i_key_negotiation> key_negotiation_;
	public:
		template<typename ... Args>
		api(Args... args) : 
			key_negotiation_(std::make_unique<key_negotiation>(args...))
			,cipher_(std::make_unique<cipher>())
		{
		}
		~api() = default;
		//TODO add msg signature option
		std::string encrypt(const std::string& cli_pub_key, const std::string& data) {
			return cipher_->encrypt(key_negotiation_->get_cipher_key(cli_pub_key), data);
		}
		std::string decrypt(const std::string& cli_pub_key, const std::string& data) {
			return cipher_->decrypt(key_negotiation_->get_cipher_key(cli_pub_key), data);
		}
		std::string get_prime() {
			return key_negotiation_->get_prime();
		}
		void set_prime(const std::string& prime, const std::string& gen = "2") {
			key_negotiation_->set_prime(prime, gen);
		}
		std::string get_pub_key() {
			return key_negotiation_->get_pub_key();
		}
		std::string generate_cert(const std::string& name) {
			return static_cast<certificate*>(this)->generate_cert(name);
		}
		void set_cert(const std::string& cert) {
			return static_cast<certificate*>(this)->set_cert(cert);
		}
		int verify_cert(const std::string& cert) {
			return static_cast<certificate*>(this)->verify_cert(cert);
		}
		std::string sign_cert(const std::string& csr_cert) {
			return static_cast<certificate*>(this)->sign_cert(csr_cert);
		}
	};
	
	template <typename key_negotiation, typename cipher>
	class server_certificate : public api<server_certificate<key_negotiation, cipher>, key_negotiation, cipher>
	{
		std::unique_ptr<x509_certificate> cert_;
	public:
		template<typename ... Args>
		server_certificate(Args&& ... args) : 
			api<server_certificate<key_negotiation, cipher>, key_negotiation, cipher>(std::forward<Args>(args)...), 	
			cert_(std::make_unique<x509_certificate>())
		{}

		void set_cert(const std::string& cert) {
			cert_->set_cert_ca(cert);
		}
		//TODO use std::string_view
	 	std::string generate_cert(const std::string& name) {
			cert_->generate_self_signed_ca(name);	
			return cert_->x509_to_pem();
		}
	
		std::string sign_cert(const std::string& pem_req) {
			auto csr = cert_->pem_to_x509req(pem_req);
			auto sign_cert  = cert_->sign_csr(csr.get());
			return cert_->x509_to_pem(sign_cert.get()); 
		}

		int verify_cert(const std::string& cert) {
			//Server verify clients certificates
			if(cert.empty()) {
				return -1;
			}
			//TODO server must control cert's in case of date expiration, i.e. need to add cert's in queue
			auto certificate = cert_->pem_to_x509req(cert);
			//verify
		 	return cert_->parse_x509_csr(certificate.get());
		}
	};

	/*template<typename... Args>
	server_certificate(Args&&...) -> server_certificate<std::decay_t<Args>...>;*/
	
	template <typename key_negotiation, typename cipher>
	class client_certificate : public api<client_certificate<key_negotiation, cipher>, key_negotiation, cipher>
	{
		std::unique_ptr<x509_certificate> cert_;
		
	public:
		template<typename ... Args>
		client_certificate(Args&& ... args) :
			api<client_certificate<key_negotiation, cipher>, key_negotiation, cipher>(std::forward<Args>(args)...), 	
			cert_(std::make_unique<x509_certificate>())
		{}
	
		void set_cert(const std::string& cert) {
			//cert_->set_cert_ca(cert);
			//cert_->set_cert_csr(cert); //TODO 
		}	

		std::string generate_cert(const std::string& client_name) {
			cert_->generate_csr(client_name);
			return cert_->x509req_to_pem();
		}
		
		std::string sign_cert(const std::string& pem_req) {
			throw std::logic_error("need to realise it, seems useful feature");
		};

		int verify_cert(const std::string& cert) {
			int res = -1;
			//Client verify certificates from server
			if(cert.empty()) {
				return res;
			}
			auto certificate = cert_->pem_to_x509(cert);
			//TODO if(is_root_cert(certificate))
			if(!is_root_cert_set()) {
				//verify
				res = cert_->parse_x509_ca(certificate.get());
				if(!res) { 
					cert_->set_root_cert(std::move(certificate));
				}
			}
			else {
				res = cert_->parse_x509_ca(certificate.get(), cert_->root_cert_.get());	
			}
			return res;
		}
	private:
		bool is_root_cert_set() {
			return cert_->is_root_cert_set();
		}
	};

	//TODO use sfinae instead of constexpr
	template <typename Policy, typename Proto, typename Cipher, typename ... Args, std::enable_if_t<(sizeof...(Args) <= 10)>* = nullptr>
 	auto get_api(Args... args) {
		if constexpr(std::is_same<Policy, ServerPolicy>::value) {
 			return std::make_shared<server_certificate<Proto, Cipher>>(args...);
		}
		else if constexpr(std::is_same<Policy, ClientPolicy>::value) {
			return std::make_shared<client_certificate<Proto, Cipher>>(args...);
		}
 	}

} // namespace crypto
} // namespace playclose
