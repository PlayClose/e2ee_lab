#pragma once
#include <chrono>
#include <boost/asio.hpp>
#include <cryptoapi/crypto_api.h>
#include <include/msg_e2e.h>
#include <include/msg_cli_srv.h>
#include "db.h"


namespace playclose {
	namespace server {

	using boost::asio::ip::tcp;

	auto constexpr key_size = 128;
	auto constexpr msg_size = 16;
	auto constexpr buf_size = 2000;

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
		std::unique_ptr<misc::msg_e2e<Proto, Cipher, C>> msg_e2e_;
		std::unique_ptr<misc::msg_cli_srv<Proto, Cipher, C>> msg_;
		std::vector<std::shared_ptr<session<Proto, Cipher>>>& connections_;
		boost::asio::cancellation_signal cancel_signal_;
	public:
		session(boost::asio::io_context& io_context, int id, std::vector<std::shared_ptr<session<Proto, Cipher>>>& connections,
			const std::string& prime, std::function<std::string (void)> callback) :
			crypt_(crypto::get_api<crypto::ServerPolicy, Proto, Cipher>(512, 2)),
			msg_e2e_(std::make_unique<misc::msg_e2e<Proto, Cipher, C>>(crypt_, [this]{return cli_pub_key_;})),
			msg_(std::make_unique<misc::msg_cli_srv<Proto, Cipher, C>>(crypt_, [this]{return cli_pub_key_;})), //TODO mb there is using another key
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
			msg_e2e_(std::make_unique<misc::msg_e2e<Proto, Cipher, C>>(crypt_, [this]{return cli_pub_key_;})),
			msg_(std::make_unique<misc::msg_cli_srv<Proto, Cipher, C>>(crypt_, [this]{return cli_pub_key_;})),
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
			buf_.resize(buf_size);
			socket_.async_read_some(boost::asio::buffer(buf_, buf_size), 			
				[this](boost::system::error_code const& er, size_t size) 
					{
						if(er) {
							//TODO stop client in case of error
							std::cout << "__dbg_ read error: " << buf_; //TODO add async logging
						}
						else {	
							auto [cmd, data] = msg_->parse_msg_cli_srv(buf_);
							std::cout << "RCV cmd: "<< cmd << " data: " << data << std::endl;
				
							if(cmd == "sign certificate") {
								auto sign_csr_cert = crypt_->sign_cert(data);
								auto [header, payload] = msg_->build_msg(cmd, sign_csr_cert);
								write_cli_srv(header + payload);
							}
							else if(cmd == "get prime") {
								auto prime = crypt_->get_prime();
								auto [header, payload] = msg_->build_msg(cmd, prime);
								write_cli_srv(header + payload);
							}
							else if(cmd == "pubkey") {
								cli_pub_key_ = data;	
								auto srv_pub_key = crypt_->get_pub_key();
								auto [header, payload] = msg_->build_msg(cmd, srv_pub_key);
								write_cli_srv(header + payload);
							}	
							else if(cmd == "connect id") {
								auto [header, payload] = msg_->build_msg(cmd, str_id_, playclose::misc::msg_attribute::encrypt);
								write_cli_srv(header + payload);

							}
							else if(cmd == "connect prime") {
								auto [header, payload] = msg_->build_msg(cmd, prime_, playclose::misc::msg_attribute::encrypt);
								write_cli_srv(header + payload);

							}
							else if(cmd == "id and key") {
								auto pos = data.find(':');
								std::string id = data.substr(0, pos);
								std::string pub_key = data.substr(pos+1);
								db::get_instance()->save_key(id, pub_key);
								auto [header, payload] = msg_->build_msg(cmd, "accepted", playclose::misc::msg_attribute::encrypt);
								write_cli_srv(header + payload);
							}
							else if(cmd == "cli list") {
								auto [header, payload] = msg_->build_msg(cmd, db::get_instance()->serialize_keys(), 
																				playclose::misc::msg_attribute::encrypt);
								write_cli_srv(header + payload);
							}
							else {			
								std::runtime_error("command is not supported");
							}
						}
					});
		}
		
		void cli_srv_channel() {
			if(pem_ca_callback_) {
				crypt_->set_cert(pem_ca_callback_());
				write_cli_srv(pem_ca_callback_());
			}
			else {
				throw std::runtime_error("root certificate is not set");
			}
		}
	
		void read_e2e() {
			buf_.clear();
			buf_.resize(buf_size);
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
								auto payload = msg_e2e_->transfer_e2e(buf_, src, dst);
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
							auto [attr, payload] = msg_e2e_->transfer_e2e(buf_, src, dst);
							if(src == dst) {
								str_id_ = src;
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
