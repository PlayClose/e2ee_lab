#pragma once

#include <include/misc.h>

namespace playclose {
	namespace misc {
	
	template <	
		typename Proto, 
		typename Cipher, 
		template <typename, typename> typename C, 
		typename Cert = C<Proto, Cipher>>
	class msg_cli_srv {
		std::shared_ptr<crypto::api<Cert, Proto, Cipher>>& crypt_;	
		std::function<std::string (void)> get_cli_pub_key_;
	public:
		template <typename Func>
		msg_cli_srv(std::shared_ptr<crypto::api<Cert, Proto, Cipher>>& crypt, Func&& callback) :
			crypt_(crypt),
			get_cli_pub_key_(std::forward<Func>(callback))
		{}
		~msg_cli_srv() = default;

		// |attr|payload_size|payload:{cmd_size|cmd|data}|
		//@return std::pair<header, payload>
		std::pair<std::string, std::string> build_msg(const std::string& cmd, const std::string& data = "", 
														msg_attribute flag = msg_attribute::none) {
			std::string header;
			header.resize(attr_length_size + payload_length_size);
			auto pos = 0;
			memcpy(header.data() + pos, std::to_string(static_cast<uint8_t>(flag)).data(), attr_length_size);
			pos = attr_length_size;

			std::string payload;
			payload.resize(cmd_length_size + cmd.size() + data.size());
			sprintf(payload.data(), "%3ld", cmd.size());
			memcpy(payload.data() + cmd_length_size, (cmd + data).data(), cmd.size() + data.size());	
			
			if(flag == msg_attribute::encrypt) {
				payload = crypt_->encrypt(get_cli_pub_key_(), payload);
			}

			sprintf(header.data() + pos, "%4ld", payload.size());

			return std::make_pair(header, payload);
			
		}
		//@return std::pair<cmd, data>	
		std::pair<std::string, std::string> parse_msg_cli_srv(const std::string& buf) {
			auto attr = std::stoi(buf.substr(0, attr_length_size));
			auto pos = attr_length_size;
			auto payload_size = std::stoi(buf.substr(pos, payload_length_size));
			pos += payload_length_size;
			std::string payload = buf.substr(pos, payload_size);
			if(attr == static_cast<uint8_t>(msg_attribute::none)) {
				auto pos = 0;
				auto cmd_size = std::stoi(payload.substr(pos, cmd_length_size));
				pos = cmd_length_size;
				auto cmd = payload.substr(pos, cmd_size);
				pos += cmd_size;
				auto data_size = payload_size - cmd_size - cmd_length_size;
				auto data = payload.substr(pos, data_size);

				return std::make_pair(cmd, data);
			}
			else if(attr == static_cast<uint8_t>(msg_attribute::encrypt)) {
				std::string decrypt_payload = crypt_->decrypt(get_cli_pub_key_(), payload);
				auto pos = 0;
				auto cmd_size = std::stoi(decrypt_payload.substr(pos, cmd_length_size));
				pos = cmd_length_size;
				auto cmd = decrypt_payload.substr(pos, cmd_size);
				pos += cmd_size;
				auto data_size = payload_size - cmd_size - cmd_length_size;
				auto data = decrypt_payload.substr(pos, data_size);
				
				return std::make_pair(cmd, data);
			}
			else{
				throw std::runtime_error("attribut is not supported: " + std::to_string(attr));
			}
		}
	};

	} // namespace misc
} // namespace playclose
