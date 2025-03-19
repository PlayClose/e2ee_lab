#include <boost/asio.hpp>
#include "session.h"

namespace playclose {
	namespace server {

	using boost::asio::ip::tcp;
	template<typename Proto, typename Cipher>
	class e2e_node 
	{
	private:
		boost::asio::io_context& io_context_;
		tcp::acceptor acceptor_;
		std::unique_ptr<boost::asio::io_service::work> worker_;	
		std::vector<std::shared_ptr<session<Proto, Cipher>>> connections_;

	public:
		e2e_node(boost::asio::io_context& io_context, int port)
			: io_context_(io_context),
			  worker_(std::make_unique<boost::asio::io_service::work>(io_context)),
			  acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
		{
			start_accept();
			main_task();
		}

	private:
		void main_task() {
			boost::asio::post(io_context_, 
				[this](){
					while(1) {
						std::this_thread::sleep_for(std::chrono::milliseconds(1));
						for(const auto& i : connections_) {
							if(!i->str_id_.empty()) {
								//проверить базу данных для этого пользователя, если сообщений нет, слушать.
								//иначе извлечь сообщение из бд 
								auto db_data = db::get_instance()->get_data(i->str_id_);
								if(db_data.size()) {
									//если сообщения есть, то отправить
									for(const auto& data : db_data) {
										//операция записи имеет право на отмену операции чтения
										i->request_cancel();
										if(i->get_state() == state::free || i->get_state() == state::writing) {
											i->write_e2e(data);
											db::get_instance()->delete_data(i->str_id_, data);
										}
									}
								}
								else if(i->get_state() == state::free) {
									i->read_e2e();
								}
							}
						}
					}
				});
		}
		
		void start_accept() {
			auto new_connection = std::make_shared<session<Proto, Cipher>>(io_context_, connections_);
			acceptor_.async_accept(new_connection->socket(),
				boost::bind(&e2e_node::handle_accept, this, new_connection,
					boost::asio::placeholders::error)); }

		void handle_accept(std::shared_ptr<session<Proto, Cipher>> new_connection,
			const boost::system::error_code& error) {
			if (!error) {
				std::cout << "Add connection: "
					<< new_connection->socket().remote_endpoint().address().to_string()
					<< ":" << new_connection->socket().remote_endpoint().port() << '\n';
				
				connections_.push_back(new_connection);
				
				boost::asio::post(io_context_, 
						[new_connection](){
							std::cout << "e2e get client pubkey and id..." << std::endl;
							new_connection->read_pubkey_and_id();
						});

			}
			start_accept();
		}
	};
	} // namespace server
} // 
