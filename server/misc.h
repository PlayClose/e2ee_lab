#pragma once

auto constexpr src_dst_size = 3;

std::string build_msg(const std::string& src, const std::string& dst, const std::string& data)
{
	if( src.length() == src_dst_size || dst.length() == src_dst_size) {
		throw std::runtime_error("Bad src or dst: " + src + " " + dst);
	}

	return src + dst + data;
}
