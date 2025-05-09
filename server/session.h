#pragma once
#include <chrono>
#include <boost/asio.hpp>
#include <cryptoapi/crypto_api.h>
#include <include/msg.h>
#include "db.h"


namespace playclose {
	namespace server {

	using boost::asio::ip::tcp;

	auto constexpr key_size = 128;
	auto constexpr msg_size = 16;
	auto constexpr buf_size = 1000;

	enum class state
	{
		init = 0,
		reading,
		writing,
		free
	}; 

	template<typename Proto, 
			 typename Cipher, 
			 template <typename, typename> typename C = crypto::server_certificate, 
			 typename Cert  = C<Proto, Cipher>>
	class session : public std::enable_shared_from_this<session<Proto, Cipher>>
	{
	public:
		int id_;
		std::mutex m_;
		std::string str_id_;
		int network_client_num_;
		std::atomic<state> state_;
		std::condition_variable cv_key_negotiation_;
		std::atomic<bool> start_key_negotiation_; // start key negotiation process
		std::string prime_;
		std::function<std::string (void)> pem_ca_callback_;

	private:
		//boost::asio::streambuf buf_;
		std::string buf_; //TODO make std::vector<uint8_t> ?
		//std::vector<uint8_t> buf_
		tcp::socket socket_;
		std::string cli_pub_key_;
		std::shared_ptr<crypto::api<Cert, Proto, Cipher>> crypt_;
		std::unique_ptr<misc::msg<Proto, Cipher, C>> msg_;
		std::vector<std::shared_ptr<session<Proto, Cipher>>>& connections_;
		boost::asio::cancellation_signal cancel_signal_;
	public:
		session(boost::asio::io_context& io_context, int id, std::vector<std::shared_ptr<session<Proto, Cipher>>>& connections,
			const std::string& prime, std::function<std::string (void)> callback) :
			crypt_(crypto::get_api<crypto::ServerPolicy, Proto, Cipher>(512, 2)),
			msg_(std::make_unique<misc::msg<Proto, Cipher, C>>(crypt_, [this]{return cli_pub_key_;})),
			socket_(io_context),
			str_id_(std::to_string(id)),
			connections_(connections),
			state_(state::init),
			prime_(prime),
			pem_ca_callback_(callback)
		{
			buf_.resize(buf_size);
		};
		session(boost::asio::io_context& io_context, std::vector<std::shared_ptr<session<Proto, Cipher>>>& connections) :
			crypt_(crypto::get_api<crypto::ServerPolicy, Proto, Cipher>(512, 2)),
			msg_(std::make_unique<misc::msg<Proto, Cipher, C>>(crypt_, [this]{return cli_pub_key_;})),
			socket_(io_context),
			connections_(connections),
			state_(state::init),
			str_id_{},
			prime_{},
			pem_ca_callback_{}
		{
			buf_.resize(buf_size);
		};
		~session() = default;
	
		state get_state() {
			return state_.load();	
		}
		void set_state(state s) {
			state_.store(s);
		}

		void write_cli_srv(const std::string& message) {
				boost::asio::async_write(socket_, boost::asio::buffer(message),
					boost::bind(&session::handle_write_cli_srv, this->shared_from_this(),
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred));
		}
		void handle_write_cli_srv(const boost::system::error_code& , size_t size){
			read_cli_srv();
		}

		void read_cli_srv() {
			buf_.clear();
			buf_.resize(1000);
			socket_.async_read_some(boost::asio::buffer(buf_, buf_size), 			
				[this](boost::system::error_code const& er, size_t size) 
					{
						if(er) {
							//TODO stop client in case of error
							std::cout << "__dbg_ read error: " << buf_; //TODO add async logging
						}
						else {	
							std::cout << "RCV raw: " << buf_ << " size: " << buf_.size() <<  std::endl;
							std::string str_msg_size = buf_.substr(0, 3);
							int int_msg_size = std::stoi(str_msg_size);
							buf_ = buf_.substr(3, int_msg_size);
							std::cout << "RCV: " << buf_ << " size: " << buf_.size() << std::endl;
							//TODO сделать нормальный протокол cli<->srv
							if(int_msg_size == key_size) {
								cli_pub_key_ = buf_;
								write_cli_srv(crypt_->get_pub_key());
							}
							else {
								buf_ = crypt_->decrypt(cli_pub_key_, buf_);
								std::string cmd = buf_.substr(0,16);
								std::cout << "Decrypted: " << cmd << std::endl;
								//cmd, i.e. client server talking
								if(cmd == "connect_with_cli") {	
									//send own client id, cause client doesn't know his id
									//тут надо отправить прайм единый для всех пользователей
									std::string prime_msg = crypt_->encrypt(cli_pub_key_, str_id_ + prime_);
									write_cli_srv(std::to_string(prime_msg.size()) + prime_msg);
								}
								else if(cmd == "gets_list_of_cli") {
									std::string crypt_msg = crypt_->encrypt(cli_pub_key_, db::get_instance()->serialize_keys());	
									write_cli_srv(std::to_string(crypt_msg.size()) + crypt_msg);
								}
								else if(cmd == "_pub_cli_key_id_") {
										std::string str_id = buf_.substr(16, 3);	
										std::string cli_pub_key = buf_.substr(19, 128); 
										db::get_instance()->save_key(str_id, cli_pub_key);
										std::string msg = "key_accepted____";
										write_cli_srv("016" + crypt_->encrypt(cli_pub_key_, msg));
								}
								else {
									std::cout << "cmd is not defined: " << cmd << std::endl;
								}
							}
						}
					});
		}
		
		void cli_srv_channel() {
			 write_cli_srv(crypt_->get_prime());
			//TODO send root certificate
			//auto root_cert = crypt_->generate_x509();
			//auto msg = crypt_->X509_to_pem();
			//write_cli_srv(msg);
		}
	
		void e2e_channel_read() {
			read_e2e();	
		}	
		void e2e_channel_write(const std::string& msg) {	
			write_e2e(msg);
		}
		void read_e2e() {
			buf_.clear();
			buf_.resize(1000);
			set_state(state::reading);
			socket_.async_read_some(boost::asio::buffer(buf_, buf_size),
				boost::asio::bind_cancellation_slot(
  					cancel_signal_.slot(), 			
					[this](boost::system::error_code const& er, size_t size) 
						{
							if(er) { 
								if(er != boost::system::errc::errc_t::operation_canceled) {	 
									std::cout << "__dbg_ read error: " << buf_;
									std::cout << "__dbg_ error code: " << er << std::endl;
								}
							}
							else {	
								std::string src, dst;
								auto payload = msg_->transfer_e2e(buf_, src, dst);
								if(!payload.second.empty()) { //TODO for what? to avoid null msg?
									db::get_instance()->save(dst, payload.first + payload.second);
								}
								set_state(state::free);
							}
						}
					)
			);
		}

		void request_cancel() {
			cancel_signal_.emit(boost::asio::cancellation_type::total);
			set_state(state::free);
		}
		
		void write_e2e(const std::string& msg) {
			std::cout << "id: " << str_id_ << " SND: " << msg << std::endl;
			set_state(state::writing);
			boost::asio::async_write(socket_, boost::asio::buffer(msg),
				boost::bind(&session::handle_write_e2e, this->shared_from_this(),
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		}
		
		void handle_write_e2e(const boost::system::error_code& , size_t size){
			set_state(state::free);
		}	

		void read_pubkey_and_id() {
			socket_.async_read_some(boost::asio::buffer(buf_, buf_size), 			
				[this](boost::system::error_code const& er, size_t size) 
					{
						if(er) {
							//TODO stop client there
							std::cout << "__dbg_ read error: " << buf_;
						}
						else {	
							std::string src, dst;
							auto payload = msg_->transfer_e2e(buf_, src, dst);
							if(src == dst) { //TODO check attr if need it
								str_id_ = src;
								cli_pub_key_ = payload.second;
							}
							else {
								//TODO stop client there
								throw(std::logic_error("Oops. Protocol error."));
							}
							set_state(state::free);
						}
					});
		}

		tcp::socket& socket() {
			return socket_;
		}
	};
	} //namespace server
} //namespace playclose 
