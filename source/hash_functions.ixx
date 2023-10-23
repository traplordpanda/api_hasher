module;

#include <string_view>

export module hash_functions;

namespace hash_functions
{

	export constexpr auto simple_hash_func(std::string_view str) -> std::uint32_t
	{
		std::uint32_t hash = 0x35;
		for (char ch : str)
		{
			hash += (hash * 0xab10f29f + static_cast<unsigned char>(ch)) & 0xffffff;
		}
		return hash;
	}

	export constexpr auto fnva1(std::string_view str) -> std::uint32_t
	{

		std::uint32_t hash = 0x811c9dc5;
		constexpr std::uint32_t prime = 0x1000193;
		if (str.empty()) return hash;
		for (char ch : str)
		{
			hash = hash ^ ch;
			hash *= prime;
		}
		return hash;
	}


} // namespace hash_functions
