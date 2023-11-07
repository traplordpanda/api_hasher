import api_hash;
import hash_functions;

#include <Windows.h>
#include <bit>
#include <compare>
#include <format>
#include <iostream>
#include <stdio.h>
void message_box_example() {
    // decide which hash function we want to use
    // can provide your own function this is just an example
    // function needs to be constexpr
    constexpr auto hf = hash_functions::fnva1;

    // compile time hash function no string stored
    // fnva1 MessageBoxA == 0x23a979e4
    constexpr auto msgboxhash = hf("MessageBoxA");

    // init ApiHasher object
    // takes variadic list of dll names
    auto api_hasher = ApiHasher{hf, "user32.dll", "kernel32.dll"};

    // lookup method if you need raw function pointer
    // look up for hash 0x23a979e4
    auto mbox_address = api_hasher.resolve_function_hash(msgboxhash);
    auto mboxadd_print = std::bit_cast<std::uint64_t>(mbox_address);
    std::cout << std::format("\nhash : {:x} found at address {:x}\n",
                             msgboxhash, mboxadd_print);

    // convenience method using functionPointerWrap class to wrap a function
    // pointer templated to function signature <return type>(api_hash,
    // params...) messageboxa would  be equivilant to
    // ApiHasher::call_hashed_function<int>(api_hash, HWND, LPCSTR, LPCSTR,
    // UINT);
    api_hasher.call_hashed_function<int>(msgboxhash, nullptr, "hello world",
                                         "hashed api call!", MB_OK);
}
template <typename hash_function>
std::string get_cname(ApiHasher<hash_function> &api_hasher, const auto fhash) {
    // example using functionPointerWrap class
    // convenience class to wrap function pointers
    // template parameters are the function return type,
    // and function args...
    auto cname_address = api_hasher.resolve_function_hash(fhash);
    if (not cname_address) {
        std::cout << "hash : 0x" << std::hex << fhash << " not found\n";
        return "";
    }
    char cname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    using fp = functionPointerWrap<bool, LPSTR, LPDWORD>;
    fp cname_api_call(cname_address);
    if (cname_api_call(cname, &size)) {
        return cname;
    }
    return "";
}

int main() {
    // decide which hash function we want to use
    // can provide your own function this is just an example
    // function should be constexpr
    constexpr auto hf = hash_functions::fnva1;
    // sysinfo example
    auto sysinfo_hash = hf("GetSystemInfo");

    // init ApiHasher object
    // takes variadic list of dll names
    auto api_hasher = ApiHasher{hf, "user32.dll", "kernel32.dll", "ws2_32.dll"};
    //,         "wsock32.dll"
    api_hasher.add_libarary("kernel32");
    if (not api_hasher.resolve_function_hash(sysinfo_hash)) {
        std::cout << "hash : 0x" << std::hex << sysinfo_hash << " not found\n";
        return 0;
    }
    SYSTEM_INFO sys_info;
    api_hasher.call_hashed_function<void>(sysinfo_hash, &sys_info);
    std::cout << std::format(
        "\nHardware information\n  OEM ID: {}\n  Number of Processors: {}\n  "
        "Page Size: {}\n  Processor type: {}\n  Minimum application address: "
        "{}\n  Maximum application address: {}\n  Active Processor Mask {}\n",
        sys_info.dwOemId, sys_info.dwNumberOfProcessors, sys_info.dwPageSize,
        sys_info.dwProcessorType, sys_info.lpMinimumApplicationAddress,
        sys_info.lpMaximumApplicationAddress, sys_info.dwActiveProcessorMask);
    
    constexpr auto cnamehash = hf("GetComputerNameA");
    const auto cname = get_cname(api_hasher, cnamehash);
	std::cout << std::format("  CNAME: {}\n", cname);
     return 0;
}
