# api_hasher

to quickly be able to test out hashing algorithms for win32 api resolution
See examples for usage.

## Installation
Requires cmake 3.28 and msvc 2022 17.1 due to C++ 20 modules.
hashing algorithms are exported in hash_function module.

## Usage
```cpp
import api_hash;
import hash_functions;

#include <compare>
#include <Windows.h>
#include <functional>
#include <iostream>

int main() {
	// decide which hash function we want to use
	constexpr auto hf = hash_functions::fnva1;

	// compile time hash string
	// fnva1 MessageBoxA == 0x23a979e4
	constexpr auto msgboxhash = hf("MessageBoxA");
	
	// intialize hashing object	
	auto fh = functionResolver{ "user32.dll", hf};

	// perform lookup for hash 0x23a979e4
	auto mbox_address = fh.resolve_function_hash(msgboxhash);
	std::cout << "\nMessageBoxA hash : 0x" << std::hex << msgboxhash << '\n';
	if (not mbox_address) {
		std::cout << "\nmessage box address not found\n";
		return 0;
	}
	std::cout << "\nmessage box address found : 0x" << std::hex << mbox_address << '\n';
	
	// convenience class to wrap a function pointer
	// templated to function signature <return type, params...>
	// messageboxa would  be equivilant to functionPointerWrap<int, HWND, LPCSTR, LPCSTR, UINT>(mbox_address);
	using custom_messageboxa = functionPointerWrap<int, HWND, LPCSTR, LPCSTR, UINT>;
    custom_messageboxa wrappedFunction(mbox_address);
    wrappedFunction(nullptr, "Hello World!", "Hashed api call!", MB_OK);
	return 0;
}
```

Debug statements

![resources/example.png](resources/example1.png)

No MessageBoxA import from example

![resources/imports.png](resources/imports.png)
