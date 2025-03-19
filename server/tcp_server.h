#include <boost/asio.hpp>
#include <cryptoapi/crypto_api.h>
#include "session.h"

namespace playclose {
	namespace server {

	using boost::asio::ip::tcp;
	template<typename Proto, typename Cipher>
	class tcp_server
	{
	private:
		boost::asio::io_context& io_context_;
		tcp::acceptor acceptor_;
		std::unique_ptr<boost::asio::io_service::work> worker_;	
		std::vector<std::shared_ptr<session<Proto, Cipher>>> connections_;
		int connection_num_;
		std::string prime_;
	public:
		tcp_server(boost::asio::io_context& io_context, int port)
			: io_context_(io_context),
			  worker_(std::make_unique<boost::asio::io_service::work>(io_context)),
			  acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
			  connection_num_(1), // 0 - server
			  prime_("")
		{
			prime_ = crypto::get_api<Proto, Cipher>(512, 2)->get_prime();	
			start_accept();
			//tcp_server_main_task(); //TODO think about asio task for prime generation, in case of regenerate prime
		}
	private:
		void start_accept() {
			auto new_connection = std::make_shared<session<Proto, Cipher>>(io_context_, connection_num_, connections_, 
										[this]() -> std::string {return this->prime_;});
			connection_num_++;
			acceptor_.async_accept(new_connection->socket(),
				boost::bind(&tcp_server::handle_accept, this, new_connection,
					boost::asio::placeholders::error));
		}

		void handle_accept(std::shared_ptr<session<Proto, Cipher>> new_connection,
			const boost::system::error_code& error) {
			if (!error) {
				std::cout << "Add connection: "
					<< new_connection->socket().remote_endpoint().address().to_string()
					<< ":" << new_connection->socket().remote_endpoint().port() << std::endl;
				
				connections_.push_back(new_connection);

				boost::asio::post(io_context_, 
						[new_connection](){
							while(1) {
								std::unique_lock lk(new_connection->m_);
								new_connection->cv_key_negotiation_.wait(lk, 
												[new_connection]{ return new_connection->start_key_negotiation_.load(); });
								new_connection->start_key_negotiation_.store(false);
								std::cout << "Start key negotiation..." << std::endl;
								new_connection->cli_srv_channel();
							}
						});
										
			}
			new_connection->start_key_negotiation_.store(true);
			new_connection->cv_key_negotiation_.notify_one();

			start_accept();
		}
	};
	} // namespace server
} // namespace playclose
