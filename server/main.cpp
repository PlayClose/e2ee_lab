//
// server.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2024 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <ctime>
//#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <thread>

#include "tcp_server.h"
#include "e2e_node.h"

using boost::asio::ip::tcp;

template <typename Func>
void run_threads(size_t num, const Func& func) {
	if(num == 0) {
		throw(std::logic_error("Oops, thread num is " + std::to_string(num)));
	}
    std::vector<std::thread> pool;
    pool.reserve(num);
	// Тут пул потоков не нужен, т.к. одна задача запускается на поток, а дальше
	// все решается через post()
    while (--num) {
        pool.emplace_back(func);
    }
	for(auto& i : pool) {
		if(i.joinable()) {
			i.join();
		}
	}
}

int main()
{
	try
	{
		const unsigned num_threads = std::thread::hardware_concurrency();

		boost::asio::io_context io_context(num_threads);
		playclose::server::tcp_server<playclose::crypto::openssl_dh, playclose::crypto::aes> server(io_context, 9090);
		playclose::server::e2e_node<playclose::crypto::openssl_dh, playclose::crypto::aes> e2e(io_context, 9091);

		run_threads(num_threads, [&io_context] {
			io_context.run();
    	});
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}

	return 0;
}

