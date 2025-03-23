//
// client.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2024 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <array>
#include <iostream>
#include <thread>
#include <chrono>
#include <boost/asio.hpp>
#include <cryptoapi/crypto_api.h>
#include <cryptoapi/misc.h>
#include <include/msg.h>

using boost::asio::ip::tcp;
auto constexpr delay = 1000;

std::string find_key_in_list(const std::string& list, const std::string& dst);

int main(int argc, char* argv[])
{
	try
	{
		if (argc != 2)
		{
		  std::cerr << "Usage: client <host>" << std::endl;
		  return 1;
		}

		boost::asio::io_context io_context;
		tcp::resolver resolver(io_context);
		tcp::socket socket(io_context);
		boost::asio::connect(socket, resolver.resolve(argv[1], "9090"));

		std::string buf;
		buf.resize(1000);
		boost::system::error_code error;

		//RCV prime
		size_t len = socket.read_some(boost::asio::buffer(buf), error);
		if (error == boost::asio::error::eof)
			return -1; // Connection closed cleanly by peer.
		else if (error)
			throw boost::system::system_error(error); // Some other error.

		auto crypt = playclose::crypto::get_api<playclose::crypto::openssl_dh, playclose::crypto::aes>(buf, "2");
		std::cout << "RCV prime: " << buf << std::endl;
		std::cout << std::endl;

		//SND cli_pub_key
		std::cout << "SND cli_pub_key: " << crypt->get_pub_key() << std::endl;
		socket.write_some(boost::asio::buffer("128" + crypt->get_pub_key()));
		
		//RCV srv_pub_key
		len = socket.read_some(boost::asio::buffer(buf), error);
		if (error == boost::asio::error::eof)
			return -1; // Connection closed cleanly by peer.
		else if (error)
			throw boost::system::system_error(error); // Some other error.
		std::cout << "RCV srv_pub_key: " << buf << std::endl;
		std::string srv_pub_key = buf;
		
		//SND crypt
		std::string crypt_msg = "016" + crypt->encrypt(srv_pub_key, "connect_with_cli");
		std::cout << "SND crypt: " << crypt_msg << std::endl;
		socket.write_some(boost::asio::buffer(crypt_msg));
		
		//RCV own id	
		buf.clear();
		buf.resize(1000);
		len = socket.read_some(boost::asio::buffer(buf), error);
		if (error == boost::asio::error::eof)
			return -1; // Connection closed cleanly by peer.
		else if (error)
			throw boost::system::system_error(error); // Some other error.
		
		std::string str_msg_size = buf.substr(0, 3);
		int int_msg_size = std::stoi(str_msg_size);
		buf = buf.substr(3, int_msg_size);

		std::cout << "RCV id: " << buf << std::endl;
		
		//Choose opposite id
		
		std::string id =  crypt->decrypt(srv_pub_key, buf).substr(0,1);
		std::cout << "Id: " << id << std::endl;
		std::string dst;	
		if(id == "1"){
			id = "001";
			dst = "002";
		}
		else if(id == "2") {
			id = "002";
			dst = "001";
		}
		std::cout << "Own ID: " << id << std::endl;
		std::string prime_e2e = crypt->decrypt(srv_pub_key, buf).substr(1, 128);
		std::cout << "Prime e2e: " << prime_e2e << std::endl;
		auto crypt_e2e = playclose::crypto::get_api<playclose::crypto::openssl_dh, playclose::crypto::aes>(prime_e2e, "2");
		//надо отправить pub_cli_key и id
		std::cout << "e2e cli_pub_key: " << crypt_e2e->get_pub_key() << std::endl;
		//SND crypt
		std::string e2e_pub_key_and_id = crypt->encrypt(srv_pub_key, "_pub_cli_key_id_" + id + crypt_e2e->get_pub_key());
		std::string e2e_crypt_msg = std::to_string(e2e_pub_key_and_id.size()) + e2e_pub_key_and_id;
		std::cout << "SND crypt: " << e2e_crypt_msg << std::endl;
		socket.write_some(boost::asio::buffer(e2e_crypt_msg));
		
		//read key_accepted____
		//RCV
		buf.clear();
		buf.resize(1000);
		len = socket.read_some(boost::asio::buffer(buf), error);
		if (error == boost::asio::error::eof)
			return -1; // Connection closed cleanly by peer.
		else if (error)
			throw boost::system::system_error(error); // Some other error.
		
		str_msg_size = buf.substr(0, 3);
		int_msg_size = std::stoi(str_msg_size);
		buf = buf.substr(3, int_msg_size);
		std::string cmd =  crypt->decrypt(srv_pub_key, buf);
		std::cout << "cmd: " << cmd << std::endl;		

		//------------------------------------------------------------------------------------------------------------
		//receiving pub_key of opposite node
		std::string list_of_clients;
		std::string opposite_node_pub_key;

		do {
			//show_list_of_clients
			//SND crypt
			std::string cmd {"gets_list_of_cli"};
			std::string test_crypt = crypt->encrypt(srv_pub_key, cmd);
			std::cout << crypt->decrypt(srv_pub_key, test_crypt) << std::endl;
			std::string crypt_list_of_clients = "016" + test_crypt;
			std::cout << "__dgb_ test_crypt.size(): " << test_crypt.size() << std::endl;
			//std::string crypt_list_of_clients = "064" + convert_data_to_hex(test_crypt);
			std::cout << "SND crypt: " << crypt_list_of_clients << std::endl;
			socket.write_some(boost::asio::buffer(crypt_list_of_clients));
			
			//RCV list of cli and keys
			buf.clear();
			buf.resize(1000);
			len = socket.read_some(boost::asio::buffer(buf), error);

			std::string str_msg_size = buf.substr(0, 3);
			int int_msg_size = std::stoi(str_msg_size);
			buf = buf.substr(3, int_msg_size);
			std::cout << "RCV: " << buf << " size: " << buf.size() << std::endl;

			if (error == boost::asio::error::eof)
				return -1; // Connection closed cleanly by peer.
			else if (error)
				throw boost::system::system_error(error); // Some other error.
			std::cout << "RCV list_of_clients: " << buf << std::endl;
			list_of_clients =  crypt->decrypt(srv_pub_key, buf);
			std::cout << "list_of_clients: " << list_of_clients << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(delay));

			opposite_node_pub_key = find_key_in_list(list_of_clients, dst);

		} while(opposite_node_pub_key.empty());
		//------------------------------------------------------------------------------------------------------------
		tcp::socket socket_e2e(io_context);
		boost::asio::connect(socket, resolver.resolve(argv[1], "9091"));
		std::this_thread::sleep_for(std::chrono::milliseconds(delay));
		

		//Init client on e2e_node 
		std::unique_ptr<playclose::misc::msg<playclose::crypto::openssl_dh, playclose::crypto::aes>> msg =
			std::make_unique<playclose::misc::msg<playclose::crypto::openssl_dh, playclose::crypto::aes>>
				(crypt_e2e, [opposite_node_pub_key]{return opposite_node_pub_key;});
		
		auto msg_init = msg->build_msg_e2e(id, id, crypt_e2e->get_pub_key());
		std::cout << "Init client on e2e_node SND: " + msg_init.first + msg_init.second << std::endl;
		socket.write_some(boost::asio::buffer(msg_init.first + msg_init.second));

		//std::cout << "Init client on e2e_node SND: " + id + id + "008" + "128" + crypt_e2e->get_pub_key() << std::endl;
		//socket.write_some(boost::asio::buffer(id + id + "128" + crypt_e2e->get_pub_key()));
			
		std::mutex m;
		std::condition_variable cv_snd, cv_rcv;
		std::atomic<bool> ready = true;

		std::thread recv ([&]() {
			while(1) {
				std::unique_lock<std::mutex> lock(m);
				cv_rcv.wait(lock, [&ready]{return !ready.load();});
				buf.clear();
				buf.resize(1000);
				len = socket.read_some(boost::asio::buffer(buf), error);
				if (error == boost::asio::error::eof)
					return -1; // Connection closed cleanly by peer.
				else if (error)
					throw boost::system::system_error(error); // Some other error.
				//buf = buf.substr(0, 16);
				std::cout << "RCV crypt: " << buf <<  " RCV.size(): " << buf.size() << std::endl;
				auto talk = msg->parse_msg_e2e(buf);
				std::cout << "Decrypt: " << talk << " size: " << talk.size() <<  std::endl;
				//std::cout << "Decrypt: " <<  crypt_e2e->decrypt(opposite_node_pub_key, buf) << std::endl;
				//std::cout << "RCV: " << buf << std::endl;
				ready.store(true);
				cv_snd.notify_one();
			
			}
		});
		
		std::thread send([&]() {
			while(1) {
				std::unique_lock<std::mutex> lock(m);
				cv_snd.wait(lock, [&ready]{return ready.load();});
				std::string payload = "_somedatainfo" + id + "_somedatainfo" + id;
				auto talk = msg->build_msg_e2e(id, dst, payload, playclose::misc::msg_attribute::encrypt);
				//auto talk = msg->build_msg_e2e(id, dst, payload, playclose::misc::msg_attribute::none);
				std::cout << "Talk on e2e_node SND: " + talk.first + talk.second << std::endl;
				socket.write_some(boost::asio::buffer(talk.first + talk.second));

				//std::cout << "__dbg_ payload size: " << payload.size() << std::endl;
				//std::string msg = id + dst + len + payload ;
				/*int repeat = 1;
				while(repeat--) {
					socket.write_some(boost::asio::buffer(msg));
				}*/
				std::this_thread::sleep_for(std::chrono::milliseconds(delay));
				ready.store(false);
				cv_rcv.notify_one();
			}
		});

		if(recv.joinable()) {
			recv.join();
		}
		if(send.joinable()) {
			send.join();
		}
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}

  return 0;
}

std::string find_key_in_list(const std::string& list, const std::string& dst) {
		auto pos = list.find(std::to_string(std::stoi(dst))+":");
		if(pos != std::string::npos){
			auto key = list.substr(pos+2, 128);
			return key;
		}
	return "";
}	
