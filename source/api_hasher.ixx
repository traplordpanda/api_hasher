module;

#include <boost/unordered/unordered_flat_map.hpp>
#include <string_view>
#include <iostream>
#include <string>
#include <Windows.h>

export module api_hash;

template <typename F>
concept HashFunction = requires(F func, std::string_view str) {
    { func(str) } -> std::same_as<std::uint32_t>;
};

export template<typename hash_function>
requires HashFunction<hash_function>
class functionResolver {
private:
    boost::unordered_flat_map<DWORD, PDWORD> function_table;
    HMODULE libraryBase;
    constexpr bool is_valid_string(std::string_view str) {
        if (str.empty()) return false;
        if (str[0] == '\0') return false;
        for (char ch : str) {
			if (ch < 32 || ch > 126) return false;
		}
		return true;
    }
    hash_function hf;

public:
    static constexpr DWORD get_hash_from_string(std::string_view str) {
        DWORD hash = 0x35;
        for (char ch : str)
        {
            hash += (hash * 0xab10f29f + static_cast<unsigned char>(ch)) & 0xffffff;
        }
        return hash;
    }

    explicit functionResolver(std::string_view library, hash_function hf) : hf(hf) {
        libraryBase = LoadLibraryA(library.data());
        function_table.reserve(1024);
        populate_function_hashes();
    }

    ~functionResolver() {
        if (libraryBase) {
            FreeLibrary(libraryBase);
        }
    }
    
  	
    PDWORD resolve_function_hash(DWORD hash) const {
        auto iter = function_table.find(hash);
        if (iter != function_table.end()) {
            return iter->second;
        }
        return nullptr;
    }

private:
    void populate_function_hashes() {

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(libraryBase);
        auto imageNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(libraryBase) + dosHeader->e_lfanew);

        DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        auto imageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(libraryBase) + exportDirectoryRVA);

        auto functions_rva = reinterpret_cast<PDWORD>(reinterpret_cast<DWORD_PTR>(libraryBase) + imageExportDirectory->AddressOfFunctions);
        auto names_rva = reinterpret_cast<PDWORD>(reinterpret_cast<DWORD_PTR>(libraryBase) + imageExportDirectory->AddressOfNames);
        auto ordinals_rva = reinterpret_cast<PWORD>(reinterpret_cast<DWORD_PTR>(libraryBase) + imageExportDirectory->AddressOfNameOrdinals);

        for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++) {
            DWORD_PTR functionNameVA = reinterpret_cast<DWORD_PTR>(libraryBase) + names_rva[i];
            auto functionName = reinterpret_cast<const char*>(functionNameVA);
            if (not is_valid_string(functionName)) break;

            DWORD functionNameHash = hf(functionName);

            DWORD_PTR functionAddressRVA = functions_rva[ordinals_rva[i]];
            auto functionAddress = reinterpret_cast<PDWORD>(reinterpret_cast<DWORD_PTR>(libraryBase) + functionAddressRVA);
            // output for educational purposes
            std::cout << functionName << std::hex << "\thashed string : 0x" << functionNameHash << "\tresolved address : 0x" << functionAddress << '\n';
            // Store the function address with its hash
            function_table[functionNameHash] = functionAddress;
        }
		std::cout << "Total Number of APIs hashed : " << std::dec << function_table.bucket_count() << '\n';
    }
};
