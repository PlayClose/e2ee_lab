#pragma once

namespace playclose {
	namespace misc {
	
	auto constexpr src_dst_max_size = 100; //src or dst could be 100 simbols size
	auto constexpr src_length_size = 3;
	auto constexpr dst_length_size = 3;
	auto constexpr payload_length_size = 4;
	auto constexpr attr_length_size = 1;
	auto constexpr cmd_length_size = 3;

	enum class msg_attribute : uint8_t {
		none,
		encrypt,
		decrypt
	};


		
	
	} //namespace misc
} //namespace playclose


