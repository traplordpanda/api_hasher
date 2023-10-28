import hash_functions;
import api_hash;

#include <gtest/gtest.h>
#include <Windows.h>

// Simple test to ensure that the functionResolver can resolve a known function hash
TEST(FunctionResolverTest, MessageBoxHashTest) {
    // Decide which hash function to use
    constexpr auto hf = hash_functions::fnva1;

    // compile-time hash function no string stored
    constexpr auto msgboxhash = hf("MessageBoxA");

    // init functionResolver object
    auto fh = functionResolver{hf, "user32.dll"};

    // Check if MessageBoxA's hash can be resolved
    auto mbox_address = fh.resolve_function_hash(msgboxhash);
    EXPECT_NE(mbox_address, nullptr);
}

// Simple test to ensure that the functionResolver can call a known function using its hash
TEST(FunctionResolverTest, MessageBoxCallTest) {
    // Decide which hash function to use
    constexpr auto hf = hash_functions::fnva1;

    // compile-time hash function no string stored
    constexpr auto msgboxhash = hf("MessageBoxA");

    // init functionResolver object
    auto fh = functionResolver{hf, "user32.dll"};

    // Try calling MessageBoxA using its hash
    int result = fh.call_hashed_function<int>(msgboxhash, nullptr, "hello test", "hashed api call!",
                                              MB_OKCANCEL);
    EXPECT_EQ(result, IDCANCEL);
}

// Add more tests as required...

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}