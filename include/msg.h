#pragma once

#include <memory>
#include <functional>

namespace playclose {
	namespace misc {

	auto constexpr src_dst_max_size = 100; //src or dst could be 100 simbols size
	auto constexpr src_length_size = 3;
	auto constexpr dst_length_size = 3;
	auto constexpr payload_length_size = 4;
	auto constexpr attr_length_size = 1;
	
	enum class msg_attribute : uint8_t {
		none,
		encrypt,
		decrypt
	};

	template <typename Proto, typename Cipher>
	class msg {
	private:
		std::shared_ptr<crypto::key_bank<Proto, Cipher>>& crypt_;	
		std::function<std::string (void)> get_cli_pub_key_;
	public:
		template <typename Func>
		msg(std::shared_ptr<crypto::key_bank<Proto, Cipher>>& crypt, Func&& callback) :
			crypt_(crypt),
			get_cli_pub_key_(std::forward<Func>(callback))
		{
			
		}
		// msg format for e2e: | attr + header | payload_size | payload |
		std::pair<std::string, std::string> build_msg_e2e(const std::string& src, const std::string& dst, 
															const std::string& payload, msg_attribute flag = msg_attribute::none) {
			std::string header;
			if( src.size() == 0 || dst.size() == 0) {
				throw std::runtime_error("Bad src or dst: " + src + " " + dst);
			}
			if( src.size() > src_dst_max_size || dst.size() > src_dst_max_size) {
				throw std::runtime_error("Bad src or dst: " + src + " " + dst);
			}

			header.resize(src_length_size + src.size() + dst_length_size + dst.size() + attr_length_size + payload_length_size);
			//memcpy(header.data(), std::to_string(static_cast<uint8_t>(flag)).data(), attr_length_size);
			sprintf(header.data(), "%3ld", src.size());
			auto pos = src_length_size;
			memcpy(header.data() + pos, src.data(), src.size());
			pos += src.size();
			sprintf(header.data() + pos, "%3ld", dst.size());
			pos += dst_length_size;
			memcpy(header.data() + pos, dst.data(), dst.size());
			pos += dst.size();
			memcpy(header.data() + pos, std::to_string(static_cast<uint8_t>(flag)).data(), attr_length_size);
			pos += attr_length_size;
			sprintf(header.data() + pos, "%4ld", payload.size());
			

			if(flag == msg_attribute::none) {
				return std::make_pair(header, payload);
			}
			else if (flag == msg_attribute::encrypt) {
				return std::make_pair(header, crypt_->encrypt(get_cli_pub_key_(), payload));
			}
			else {
				throw(std::logic_error("attribute not supported"));
			}
		}
	
		std::string parse_msg_e2e(const std::string& buf) {
			auto attr = std::stoi(buf.substr(0, attr_length_size));
			auto pos = attr_length_size;
			auto payload_size = std::stoi(buf.substr(pos, payload_length_size));
			pos += payload_length_size;
			std::string payload = buf.substr(pos, payload_size);
			if(attr == static_cast<uint8_t>(msg_attribute::none)) {
				return payload;
			}
			else if(attr == static_cast<uint8_t>(msg_attribute::encrypt)) {
				return crypt_->decrypt(get_cli_pub_key_(), payload);
			}
			else{
				throw std::runtime_error("attribut is not supported: " + std::to_string(attr));
			}
		}

		std::pair<std::string, std::string>  transfer_e2e(const std::string& buf, std::string& src, std::string& dst) {
			auto src_size = std::stoi(buf.substr(0, src_length_size));
			auto pos = src_length_size;
			src = buf.substr(pos, src_size);
			pos += src_size;
			auto dst_size = std::stoi(buf.substr(pos, dst_length_size));
			pos += dst_length_size;
			dst = buf.substr(pos, dst_size);
			pos += dst_size;

			auto attr = buf.substr(pos, attr_length_size);
			pos += attr_length_size;
			auto payload_size = buf.substr(pos, payload_length_size); 
			pos += payload_length_size;
			auto payload = buf.substr(pos, std::stoi(payload_size));	
		
			return std::make_pair(attr + payload_size, payload);
		}
	};

	} // namespace misc
} // namespace playclose
