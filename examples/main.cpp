import api_hash;
import hash_functions;

#include <Windows.h>
#include <compare>
#include <format>
#include <iostream>
#include <stdio.h>

int main() {
    // decide which hash function we want to use
    // can provide your own function this is just an example
    // function needs to be constexpr
    constexpr auto hf = hash_functions::fnva1;

    // compile time hash function no string stored
    // fnva1 MessageBoxA == 0x23a979e4
    constexpr auto msgboxhash = hf("MessageBoxA");

    // init functionResolver object
    // takes variadic list of dll names
    auto fh = functionResolver{hf, "user32.dll", "kernel32.dll"};

    // lookup method if you need raw function pointer
    // look up for hash 0x23a979e4
    // auto mbox_address = fh.resolve_function_hash(msgboxhash);
    std::cout << std::format("\nhash : {:x} found at address {:x}\n", msgboxhash, msgboxhash);

    // convenience method using functionPointerWrap class to wrap a function pointer
    // templated to function signature <return type>(api_hash, params...)
    // messageboxa would  be equivilant to
    // functionResolver::call_hashed_function<int>(api_hash, HWND, LPCSTR, LPCSTR, UINT);
    fh.call_hashed_function<int>(msgboxhash, nullptr, "hello world", "hashed api call!", MB_OK);

    // sysinfo example
    constexpr auto sysinfo_hash = hf("GetSystemInfo");
    if constexpr (debug) {
        if (not fh.resolve_function_hash(sysinfo_hash)) {
            std::cout << "hash : 0x" << std::hex << sysinfo_hash << " not found\n";
            return 0;
        }
    }
    SYSTEM_INFO sys_info;
    fh.call_hashed_function<void>(sysinfo_hash, &sys_info);
    std::cout << "\nHardware information\n"
              << "  OEM ID: " << sys_info.dwOemId << '\n'
              << "  Number of processors: " << sys_info.dwNumberOfProcessors << '\n'
              << "  Page size: " << sys_info.dwPageSize << '\n'
              << "  Processor type: " << sys_info.dwProcessorType << '\n'
              << "  Minimum application address: " << sys_info.lpMinimumApplicationAddress << '\n'
              << "  Maximum application address: " << sys_info.lpMaximumApplicationAddress << '\n'
              << "  Active processor mask: " << sys_info.dwActiveProcessorMask << '\n';

    // example using functionPointerWrap class
    // convenience class to wrap function pointers
    // template parameters are the function return type,
    // and function args...
    constexpr auto cname_hash = hf("GetComputerNameA");
    auto cname_address = fh.resolve_function_hash(cname_hash);
    if (not cname_address) {
        std::cout << "hash : 0x" << std::hex << cname_hash << " not found\n";
        return 0;
    }
    char cname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    using fp = functionPointerWrap<bool, LPSTR, LPDWORD>;
    fp cname_api_call(cname_address);
    if (cname_api_call(cname, &size)) {
        std::cout << "  CNAME : " << cname << '\n';
    } else {
        std::cout << "  failed\n";
    }
    return 0;
}
