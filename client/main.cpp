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
#include <include/msg_e2e.h>
#include <include/msg_cli_srv.h>
#include <string_view>

using boost::asio::ip::tcp;
auto constexpr delay = 1000;

std::string find_key_in_list(const std::string& list, const std::string& dst);

int main(int argc, char* argv[])
{
	try
	{
		if (argc != 3)
		{
		  std::cerr << "Usage: client <host> <user_name>" << std::endl;
		  return 1;
		}

		boost::asio::io_context io_context;
		tcp::resolver resolver(io_context);
		tcp::socket socket(io_context);
		boost::asio::connect(socket, resolver.resolve(argv[1], "9090"));

		size_t len;
		std::string buf;
		buf.resize(1000);
		boost::system::error_code error;
		
		auto recv {
			[&socket]() -> std::string {
				boost::system::error_code error;
				std::string buf;
				buf.resize(2000);
				int len = socket.read_some(boost::asio::buffer(buf), error);
				std::cout << "RCV len: " << len << std::endl;
				if (error == boost::asio::error::eof)
					return std::string{}; // Connection closed cleanly by peer.
				else if (error)
					throw boost::system::system_error(error); // Some other error.	

				return buf;
			}
		};	
	
		auto send {
			[&socket](std::string_view msg) {
				socket.write_some(boost::asio::buffer(msg));
			}
		};
				
		std::string srv_pub_key_callback;	
		//Init api by default for working with certificates		
		std::shared_ptr<playclose::crypto::api<
				playclose::crypto::client_certificate<playclose::crypto::openssl_dh, playclose::crypto::aesgcm>,
				playclose::crypto::openssl_dh,
				playclose::crypto::aesgcm>>
		crypt = playclose::crypto::get_api<playclose::crypto::ClientPolicy, playclose::crypto::openssl_dh, playclose::crypto::aesgcm>(512);
		auto msg = std::make_unique<	
									playclose::misc::msg_cli_srv<
														playclose::crypto::openssl_dh, 
														playclose::crypto::aesgcm, 
														playclose::crypto::client_certificate>>
												(crypt, [&srv_pub_key_callback]{return srv_pub_key_callback;});
		//TODO certificates tasks:
		//RCV root server certificate
		auto root_cert = recv();	
		std::cout << "RCV root_cert: " << root_cert << std::endl;
		//Verify root cert
		if(crypt->verify_cert(root_cert)) {
			throw std::runtime_error("Root cert is not valid!");
		}
		//SND request for certificate signing
		std::cout << "Client name: " << argv[2] << std::endl;
		auto client_cert_req = crypt->generate_cert(argv[2]);
		std::cout << "SND client_cert_req: " << client_cert_req << std::endl;
		auto [client_cert_header, client_cert_payload] = msg->build_msg("sign certificate", client_cert_req);
		send(client_cert_header + client_cert_payload);

		//RCV certificate, signed by server
		auto [cmd, user_cert] = msg->parse_msg_cli_srv(recv());
		std::cout << "RCV certificate, signed by server: " << user_cert << std::endl;
		if(cmd == "sign sertificate") {
			if(crypt->verify_cert(user_cert)) {
				throw std::runtime_error("User cert is not valid!");
			}
			std::cout << "Cert is correct!" << std::endl;
		}
		//SND Request to prime: 
		//TODO add prime inside cert
		auto [get_prime_header, get_prime_payload] = msg->build_msg("get prime");
		std::cout << "SND: get prime" << std::endl;
		send(get_prime_header + get_prime_payload);
		//RCV prime
		auto [cmd2, prime] = msg->parse_msg_cli_srv(recv());
		if(cmd2 == "get prime") {
			crypt->set_prime(prime);
			std::cout << "RCV prime: " << prime << std::endl;
			std::cout << std::endl;
		}

		//SND cli_pub_key
		auto [pub_key_header, pub_key_payload] = msg->build_msg("pubkey", crypt->get_pub_key());
		std::cout << "SND cli pubkey: " << crypt->get_pub_key() << std::endl;
		send(pub_key_header + pub_key_payload);
		
		//RCV srv_pub_key
		auto [cmd3, srv_pub_key] = msg->parse_msg_cli_srv(recv());
		if(cmd3 != "pubkey") {
			throw std::runtime_error("expected srv pubkey, but received: " + cmd3);
		}	
		std::cout << "RCV srv pubkey: " << srv_pub_key << std::endl;
		srv_pub_key_callback = srv_pub_key;

		//SND crypt request for id
		auto [connect_header, connect_payload] = msg->build_msg("connect id", "", playclose::misc::msg_attribute::encrypt);
		std::cout << "SND crypt: connect id" << std::endl;
		send(connect_header + connect_payload);
		//RCV own id	
		auto [cmd4, id] = msg->parse_msg_cli_srv(recv());
		if(cmd4 != "connect id") {
			throw std::runtime_error("Can't process cmd: " + cmd4);
		}
		std::cout << "Own ID: " << id << std::endl;
		//SND crypt request for prime 
		auto [prime_header, prime_payload] = msg->build_msg("connect prime", "", playclose::misc::msg_attribute::encrypt);
		std::cout << "SND crypt: connect prime" << std::endl;
		send(prime_header + prime_payload);
		//RCV own id	
		auto [cmd5, prime_e2e] = msg->parse_msg_cli_srv(recv());
		if(cmd5 != "connect prime") {
			throw std::runtime_error("Can't process cmd: " + cmd5);
		}
		std::cout << "Prime e2e: " << prime_e2e << std::endl;

		//Choose opposite id
		std::string dst;
		if(id == "1"){
			dst = "2";
		}
		else if(id == "2") {
			dst = "1";
		}

		//TODO auto doesn't work, make wrapper
		std::shared_ptr<playclose::crypto::api<
				playclose::crypto::client_certificate<playclose::crypto::openssl_dh, playclose::crypto::aesgcm>,
				playclose::crypto::openssl_dh,
				playclose::crypto::aesgcm>>
		crypt_e2e = playclose::crypto::get_api<playclose::crypto::ClientPolicy,
													playclose::crypto::openssl_dh,
													playclose::crypto::aesgcm>(prime_e2e);
		std::cout << "e2e cli_pub_key: " << crypt_e2e->get_pub_key() << std::endl;
		//SND crypt id + e2e_pub_key
		auto [e2e_header, e2e_payload] = msg->build_msg("id and key", id + ":" + crypt_e2e->get_pub_key(), playclose::misc::msg_attribute::encrypt);
		send(e2e_header + e2e_payload);
		
		//RCV accepted 
		auto [cmd6, a]= msg->parse_msg_cli_srv(recv());
		std::cout << "cmd: " << cmd6 << " answer: " << a << std::endl;		

		//------------------------------------------------------------------------------------------------------------
		//receiving pub_key of opposite node
		std::string list_of_clients;
		std::string opposite_node_pub_key;
		do {
			//show_list_of_clients 
			//SND crypt "cli list"
			auto [cli_list_header, cli_list_payload] = msg->build_msg("cli list", "", playclose::misc::msg_attribute::encrypt);
			send(cli_list_header + cli_list_payload);
			//RCV cli list
			auto [cmd, list_of_clients] = msg->parse_msg_cli_srv(recv());
			if(cmd != "cli list") {
				throw std::runtime_error("Can't process cmd: " + cmd);
			}
			std::cout << "list_of_clients: " << list_of_clients << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(delay));
			opposite_node_pub_key = find_key_in_list(list_of_clients, dst);
		} while(opposite_node_pub_key.empty());
		//------------------------------------------------------------------------------------------------------------
		tcp::socket socket_e2e(io_context);
		boost::asio::connect(socket, resolver.resolve(argv[1], "9091"));
		std::this_thread::sleep_for(std::chrono::milliseconds(delay));
		
		//Init client on e2e_node 
		/*std::unique_ptr<playclose::misc::msg<playclose::crypto::openssl_dh, 
						playclose::crypto::aes, 
						playclose::crypto::server_certificate>>*/
		auto msg_e2e = std::make_unique<
									playclose::misc::msg_e2e<
														playclose::crypto::openssl_dh, 
														playclose::crypto::aesgcm, 
														playclose::crypto::client_certificate>>
								(crypt_e2e, [opposite_node_pub_key]{return opposite_node_pub_key;});
		
		//TODO aes-gcm
		//TODO double-ratchet
		//remote node must request cert by them self, i.e. blocking: client_api->verify_cert(node_id);
		auto msg_init = msg_e2e->build_msg_e2e(id, id, "");
		std::cout << "Init client on e2e_node SND: " + msg_init.first + msg_init.second << std::endl;
		socket.write_some(boost::asio::buffer(msg_init.first + msg_init.second));

		std::mutex m;
		std::condition_variable cv_snd, cv_rcv;
		std::atomic<bool> ready = true;

		std::thread receiver([&]() {
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
				std::cout << "RCV crypt: " << buf <<  " RCV.size(): " << buf.size() << std::endl;
				auto talk = msg_e2e->parse_msg_e2e(buf);
				std::cout << "Decrypt: " << talk << " size: " << talk.size() <<  std::endl;
				ready.store(true);
				cv_snd.notify_one();
			
			}
		});
		
		std::thread transmitter([&]() {
			while(1) {
				std::unique_lock<std::mutex> lock(m);
				cv_snd.wait(lock, [&ready]{return ready.load();});
				std::string payload = "now is free to write everything, wow" + id;
				auto talk = msg_e2e->build_msg_e2e(id, dst, payload, playclose::misc::msg_attribute::encrypt);
				//auto talk = msg->build_msg_e2e(id, dst, payload, playclose::misc::msg_attribute::none);
				std::cout << "Talk on e2e_node SND: " + talk.first + talk.second << std::endl;
				socket.write_some(boost::asio::buffer(talk.first + talk.second));
				/*int repeat = 1;
				while(repeat--) {
					socket.write_some(boost::asio::buffer(msg));
				}*/
				std::this_thread::sleep_for(std::chrono::milliseconds(delay));
				ready.store(false);
				cv_rcv.notify_one();
			}
		});

		if(receiver.joinable()) {
			receiver.join();
		}
		if(transmitter.joinable()) {
			transmitter.join();
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
