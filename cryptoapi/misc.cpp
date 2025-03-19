#include "misc.h"

signed char hex_digit(char c) {
    return p_util_hexdigit[(unsigned char)c];
}
std::string convert_data_to_hex(const std::string& data) {
	static const char numbers[] = "0123456789ABCDEF";
	std::string hex;
	hex.reserve(data.size() * 2);
	for (unsigned char c : data) {
		hex.push_back(numbers[c >> 4]);
		hex.push_back(numbers[c & 15]);
	}
	return hex;
}

std::string convert_hex_to_data(const std::string& hex) {
	if (hex.size() & 1) {
		throw std::runtime_error("The hex string size must be an even number.");
	}

	std::string data;
	data.reserve(hex.size() / 2);
	auto it = hex.begin();
	while (it != hex.end()) {
		int hi = hex_digit(*it++);
		int lo = hex_digit(*it++);
		if (hi == -1 || lo == -1) {
			throw std::runtime_error("Bad conversation value");
		}
		data.push_back(hi << 4 | lo);
	}
	return data;
}

std::string parse_vector(const std::vector<uint8_t> buf) {
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (auto i : buf) {
		ss << std::hex << std::setw(2) << static_cast<int>(i);
	}

	return ss.str();
}
