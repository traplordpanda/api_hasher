import api_hash;
import hash_functions;

#include <Windows.h>
#include <functional>
#include <iostream>
#include <nanobind/nanobind.h>
#include <nanobind/ndarray.h>
#include <nanobind/stl/string_view.h>
#include <nanobind/stl/unordered_map.h>
#include <string_view>

namespace nb = nanobind;

int message_box(std::string_view box_name, std::string_view box_message) {
    // decide which hash function to use
    constexpr auto hf = hash_functions::fnva1;
    constexpr auto msgboxhash = hf("MessageBoxA");
    auto fh = functionResolver{hf, "user32.dll"};
    auto mbox_address = fh.resolve_function_hash(msgboxhash);
    std::cout << "MessageBoxA hash : 0x" << std::hex << msgboxhash << '\n';
    if (not mbox_address) {
        std::cout << "\nmessage box address not found\n";
        return 0;
    }
    std::cout << "message box address found : 0x" << std::hex << mbox_address << '\n';

    // convenience class to wrap a function pointer
    // templated to function signature <return type, params...>
    // messageboxa would  be equivilant to functionPointerWrap<int, HWND, LPCSTR, LPCSTR,
    // UINT>(mbox_address);
    using custom_messageboxa = functionPointerWrap<int, HWND, LPCSTR, LPCSTR, UINT>;
    custom_messageboxa wrappedFunction(mbox_address);
    return wrappedFunction(nullptr, box_name.data(), box_message.data(), MB_OK);
}

template <typename ReturnType, typename... Args>
ReturnType call_hashed_function(std::string_view library, std::uint32_t api_hash, Args... args) {
    // Decide which hash function to use (assuming you've the hash_functions namespace defined)
    constexpr auto hf = hash_functions::fnva1;
    auto fh = functionResolver{hf, library};
    auto func_address = fh.resolve_function_hash(api_hash);

    if (not func_address) {
        throw std::runtime_error("API address not found for the provided hash.");
    } else {
        std::cout << "API hash : " << std::hex << api_hash << "\nAPI address found : 0x" << std::hex
                  << func_address << '\n';
    }
    using ApiFunction = functionPointerWrap<ReturnType, Args...>;
    ApiFunction wrappedFunction(func_address);
    return wrappedFunction(std::forward<Args>(args)...);
}

template <typename... Args>
int generic_api(std::string_view library_name, std::uint32_t api_hash, Args... args) {
    call_hashed_function<int>(library_name, api_hash, args...);
}

int message_box1() {
    constexpr auto hf = hash_functions::fnva1;
    constexpr auto msgboxhash = hf("MessageBoxA");
    return call_hashed_function<int>("user32.dll", msgboxhash, nullptr, "hello", "WORLD", MB_OK);
}

int generic_api2(std::string_view library_name, std::uint32_t api_hash, nb::args args) {
    return call_hashed_function<int>(library_name, api_hash, args);
}
std::unordered_map<DWORD, PDWORD> get_fnva1_hashes(std::string_view library) {
    constexpr auto hf = hash_functions::fnva1;
    auto fh = functionResolver{hf, library};
    return fh.get_function_table();
}

using hf = std::function<std::uint32_t(std::string_view)>;
NB_MODULE(api_hash_ext, m) {
    nb::class_<functionResolver<hf>>(m, "apiHasher")
        .def(nb::init<hf, const std::string &>())
        .def("get_values", &functionResolver<hf>::resolve_function_hash);
    m.def("message_box", &message_box);
    m.def("generic_api", &generic_api2);
    m.def("get_fnva1_hashes", &get_fnva1_hashes);
}
