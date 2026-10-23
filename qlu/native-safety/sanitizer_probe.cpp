// Copyright (c) 2026 The QLU developers
// Distributed under the MIT software license, see COPYING.
// Deliberate failures in disposable child processes prove instrumentation works.
#include <climits>
#include <iostream>
#include <string_view>

#ifndef __clang__
#error "Clang instrumentation is required"
#endif
#if !__has_feature(address_sanitizer)
#error "AddressSanitizer instrumentation is required"
#endif

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    if (std::string_view{argv[1]} == "address") {
        // Volatile index/store keeps this deliberate heap boundary violation
        // observable in optimized builds. The allocation is exactly eight bytes.
        volatile int index = 8;
        auto* bytes = new unsigned char[8]{};
        volatile unsigned char* observed = bytes;
        observed[index] = 1;
        delete[] bytes;
    } else if (std::string_view{argv[1]} == "undefined") {
        volatile int largest = INT_MAX;
        volatile int one = 1;
        volatile int overflow = largest + one;
        (void)overflow;
    } else {
        return 2;
    }
    std::cerr << "sanitizer_probe_failed_to_detect\n";
    return 0; // Unexpected success MUST make the driver fail.
}
