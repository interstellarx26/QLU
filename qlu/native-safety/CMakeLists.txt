# Test-only bounded ASan/UBSan build of QLU's actual native signing boundary.
# No node, database, or networking target is compiled or started.
cmake_minimum_required(VERSION 3.22)
project(QLUNativeSafety VERSION 1.0 LANGUAGES C CXX)
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "The native safety harness requires Clang for both C and C++")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Apply before add_subdirectory so secp's object/precomputation targets receive
# the same instrumentation as the QLU code. No recovery from sanitizer errors.
add_compile_options(-O1 -g1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all)
add_link_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
get_filename_component(QLU_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Local static test helper libraries" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "No system installation" FORCE)
set(SECP256K1_ASM OFF CACHE STRING "Instrument portable C rather than assembly" FORCE)
foreach(feature BENCHMARK TESTS EXHAUSTIVE_TESTS CTIME_TESTS EXAMPLES)
  set(SECP256K1_BUILD_${feature} OFF CACHE BOOL "Bounded safety test only" FORCE)
endforeach()
foreach(module ECDH RECOVERY MUSIG ELLSWIFT)
  set(SECP256K1_ENABLE_MODULE_${module} OFF CACHE BOOL "Hybrid signing only" FORCE)
endforeach()
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "Hybrid key derivation" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "Hybrid authorization" FORCE)
add_subdirectory("${QLU_SOURCE_ROOT}/src/secp256k1" secp256k1)

add_library(qlu-safety-crypto STATIC
  "${QLU_SOURCE_ROOT}/src/qlu/crypto.cpp"
  "${QLU_SOURCE_ROOT}/src/crypto/sha256.cpp"
  "${QLU_SOURCE_ROOT}/src/crypto/hmac_sha256.cpp"
  "${QLU_SOURCE_ROOT}/src/support/cleanse.cpp"
)
target_include_directories(qlu-safety-crypto PUBLIC "${QLU_SOURCE_ROOT}/src")
target_compile_definitions(qlu-safety-crypto PRIVATE DISABLE_OPTIMIZED_SHA256)
target_link_libraries(qlu-safety-crypto PUBLIC secp256k1 OpenSSL::Crypto)

add_library(qlu-safety-univalue STATIC
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue.cpp"
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue_get.cpp"
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue_read.cpp"
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue_write.cpp"
)
target_include_directories(qlu-safety-univalue PUBLIC "${QLU_SOURCE_ROOT}/src/univalue/include")
add_executable(qlu-keytool "${QLU_SOURCE_ROOT}/src/qlu/keytool.cpp")
target_link_libraries(qlu-keytool PRIVATE qlu-safety-crypto qlu-safety-univalue)
add_executable(qlu-native-safety native_harness.cpp)
target_link_libraries(qlu-native-safety PRIVATE qlu-safety-crypto)
add_executable(qlu-sanitizer-probe sanitizer_probe.cpp)

enable_testing()
add_test(NAME qlu_native_safety COMMAND qlu-native-safety)
set_tests_properties(qlu_native_safety PROPERTIES TIMEOUT 120)
# Deliberate-failure probes are invoked by the Python driver in separate child
# processes; CTest must never classify an unrelated process failure as proof.
