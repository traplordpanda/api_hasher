import hash_functions;
import api_hash;

#include <gtest/gtest.h>
#include <Windows.h>
#include <compare>

// Simple test to ensure that the functionResolver can call a known function using its hash
TEST(FunctionResolverTest, GetComputerNametest) {
    // Decide which hash function to use
    constexpr auto hf = hash_functions::fnva1;

    // compile-time hash function no string stored
    constexpr auto cname_hash = hf("GetComputerNameA");
    EXPECT_EQ(cname_hash, 0x446eaa3c); 
    auto fh = functionResolver{hf, "kernel32.dll"};
    auto cname_address = fh.resolve_function_hash(cname_hash);
    EXPECT_NE(cname_address, nullptr);
    char cname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
	auto result = fh.call_hashed_function<bool>(cname_hash, cname, &size);
    EXPECT_EQ(result, true);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}