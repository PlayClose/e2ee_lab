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
		std::string get_pub_key() {
			return key_negotiation_->get_pub_key();
		}
		std::string generate_cert(const std::string& name) {
			return static_cast<certificate*>(this)->generate_cert(name);
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

		//TODO use std::string_view
	 	std::string generate_cert(const std::string& name) {
			cert_->generate_self_signed_ca(name);	
			return cert_->x509_to_pem();
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

		std::string generate_cert(const std::string& client_name) {
			cert_->generate_csr(client_name);
			return cert_->x509req_to_pem();
		}
	};

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
