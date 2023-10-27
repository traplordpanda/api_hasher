module;

/**
 * @file api_hash.cpp
 * @brief Contains classes and functionalities for API hashing and function resolution.
 */

#include <Windows.h>
#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>

export module api_hash;

export constexpr bool debug = false;
/**
 * @class libraryBase
 * @brief Helper class to convert relative virtual addresses (RVA) to virtual addresses (VA).
 */
class libraryBase {
  private:
    std::uintptr_t base;

  public:
    /**
     * @brief Constructs a new libraryBase object.
     * @param base_addr The base address of the library/module.
     */
    libraryBase(std::uintptr_t base_addr) : base(base_addr) {}

    /**
     * @brief Converts an RVA to a VA.
     * @tparam T Desired pointer type of the VA.
     * @param rva The relative virtual address.
     * @return VA of type T.
     */
    template <typename T> T RVAtoVA(DWORD rva) const { return reinterpret_cast<T>(base + rva); }

    // Implicit conversion to uintptr_t
    operator uintptr_t() const { return base; }
};

// simple wrapper class to define a function prototype and make it callable using a function address
// not really safe because it takes in a raw pointer so it is on the caller

/**
 * @class functionPointerWrap
 * @brief Wraps a function pointer to make it callable.
 */
export template <typename return_type, typename... Args> class functionPointerWrap {
    // Internal type definitions for clarity
    using function_type = return_type(Args...);
    using function_pointer_type = return_type (*)(Args...);
    using function_object = std::function<function_type>;

    // private ionno
    function_object callable;

  public:
    // Constructor accepting a raw function pointer and wraps it
    functionPointerWrap(void *raw_func_pointer)
        : callable(reinterpret_cast<function_pointer_type>(raw_func_pointer)) {}

    // () operator overload to allow objects of this class to be called as functions
    return_type operator()(Args... args) { return callable(std::forward<Args>(args)...); }

    // convert to std::function if needed
    operator function_object() const { return callable; }
};

// todo : add support for variable arguments i.e. "kernel32.dll", "user32.dll"
// add optional arg to keep only specific hashes in the table

template <typename F>
concept HashFunction = requires(F func, std::string_view str) {
    { func(str) } -> std::same_as<std::uint32_t>;
};

/**
 * @class functionResolver
 * @brief Resolves function addresses using their hash values.
 */
export template <typename hash_function>
    requires HashFunction<hash_function>
class functionResolver {
  private:
    std::unordered_map<DWORD, PDWORD> function_table;
    HMODULE libbase;
    constexpr bool is_valid_string(std::string_view str) {
        if (str.empty())
            return false;
        if (str[0] == '\0')
            return false;
        for (char ch : str) {
            if (ch < 32 || ch > 126)
                return false;
        }
        return true;
    }
    hash_function hf;

  public:
    [[nodiscard]] auto get_function_table() const -> const std::unordered_map<DWORD, PDWORD> & {
        return function_table;
    }
    
    template<typename... Libs>
    explicit functionResolver(hash_function hf, Libs... libraries) : hf(hf) {
        function_table.reserve(1024);

        // lambda to handle parameter pack expansion
        auto loadlib = [this](std::string_view lib) {
			this->libbase = LoadLibraryA(lib.data());
            if constexpr (debug)
            {
			if (not libbase) {
				throw std::runtime_error("Failed to load library");
			}
				std::cout << "Loading library : " << lib << '\n';   
            }
	    this->populate_function_hashes();
        FreeLibrary(libbase);
		};
        // paramter pack expansion
		(loadlib(libraries), ...);
    }

    ~functionResolver() = default;

    [[nodiscard]] PDWORD resolve_function_hash(DWORD hash) const {
        auto iter = function_table.find(hash);
        if (iter != function_table.end()) {
            return iter->second;
        }
        return nullptr;
    }
    template <typename ReturnType, typename... Args>
    // clang-format off
    ReturnType call_hashed_function(std::uint32_t api_hash, Args... args) {
        // Decide which hash function to use (assuming you've the hash_functions namespace defined)
        auto func_address = resolve_function_hash(api_hash);
        if (not func_address) {
            throw std::runtime_error("API address not found for the provided hash.");
        }
        if constexpr (debug) {
            if (func_address) {
                std::cout << "API hash : " << std::hex << api_hash << "\nAPI address found : 0x"
                          << std::hex << func_address << '\n';
            }
        }
        using ApiFunction = functionPointerWrap<ReturnType, Args...>;
        ApiFunction wrappedFunction(func_address);
        return wrappedFunction(std::forward<Args>(args)...);
    }
    // clang-format on

  private:
    void populate_function_hashes() {
        libraryBase lib_base(reinterpret_cast<std::uintptr_t>(libbase));

        auto dos_header = lib_base.RVAtoVA<PIMAGE_DOS_HEADER>(0);
        if (not dos_header) {
            throw std::runtime_error("Invalid DOS header");
        }
        auto nt_headers = lib_base.RVAtoVA<PIMAGE_NT_HEADERS>(dos_header->e_lfanew);
        auto export_directory = lib_base.RVAtoVA<PIMAGE_EXPORT_DIRECTORY>(
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        auto functions_rva = lib_base.RVAtoVA<PDWORD>(export_directory->AddressOfFunctions);
        auto names_rva = lib_base.RVAtoVA<PDWORD>(export_directory->AddressOfNames);
        auto ordinals_rva = lib_base.RVAtoVA<PWORD>(export_directory->AddressOfNameOrdinals);

        for (DWORD i = 0; i < export_directory->NumberOfFunctions; i++) {
            auto function_name = lib_base.RVAtoVA<const char *>(names_rva[i]);
            if (not is_valid_string(function_name))
                break;

            DWORD function_hash = hf(function_name);

            auto function_addr = lib_base.RVAtoVA<PDWORD>(functions_rva[ordinals_rva[i]]);
            if constexpr (debug) {
                // output for educational purposes
                std::cout << function_name << std::hex << "\thashed string : 0x" << function_hash
                          << "\tresolved address : 0x" << function_addr << '\n';
            }
            // Store the function address with its hash
            function_table[function_hash] = function_addr;
        }
        if constexpr (debug) {
            std::cout << "Total Number of APIs hashed : " << std::dec
                      << function_table.bucket_count() << '\n';
        }
    }
};
