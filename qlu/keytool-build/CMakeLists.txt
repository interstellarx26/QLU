# QLU's offline recovery helper, built from the same pinned native sources.
# No node, database, networking service, or prebuilt origin binary is included.
cmake_minimum_required(VERSION 3.22)
project(QLURecoveryKeytool VERSION 1.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
get_filename_component(QLU_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Static local helper libraries" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "No system installation" FORCE)
foreach(feature BENCHMARK TESTS EXHAUSTIVE_TESTS CTIME_TESTS EXAMPLES)
  set(SECP256K1_BUILD_${feature} OFF CACHE BOOL "Recovery helper only" FORCE)
endforeach()
foreach(module ECDH RECOVERY MUSIG ELLSWIFT)
  set(SECP256K1_ENABLE_MODULE_${module} OFF CACHE BOOL "Recovery helper only" FORCE)
endforeach()
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "Hybrid key derivation" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "Required hybrid authorization" FORCE)
add_subdirectory("${QLU_SOURCE_ROOT}/src/secp256k1" secp256k1)

add_library(qlu-recovery-crypto STATIC
  "${QLU_SOURCE_ROOT}/src/qlu/crypto.cpp"
  "${QLU_SOURCE_ROOT}/src/crypto/sha256.cpp"
  "${QLU_SOURCE_ROOT}/src/crypto/hmac_sha256.cpp"
  "${QLU_SOURCE_ROOT}/src/support/cleanse.cpp"
)
target_include_directories(qlu-recovery-crypto PUBLIC "${QLU_SOURCE_ROOT}/src")
# Generic upstream SHA256 avoids architecture-specific object dependencies.
# It has identical hashes; this helper is not a hashing performance benchmark.
target_compile_definitions(qlu-recovery-crypto PRIVATE DISABLE_OPTIMIZED_SHA256)
target_link_libraries(qlu-recovery-crypto PRIVATE secp256k1 OpenSSL::Crypto)

add_library(qlu-recovery-univalue STATIC
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue.cpp"
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue_get.cpp"
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue_read.cpp"
  "${QLU_SOURCE_ROOT}/src/univalue/lib/univalue_write.cpp"
)
target_include_directories(qlu-recovery-univalue PUBLIC "${QLU_SOURCE_ROOT}/src/univalue/include")
add_executable(qlu-keytool "${QLU_SOURCE_ROOT}/src/qlu/keytool.cpp")
target_link_libraries(qlu-keytool PRIVATE qlu-recovery-crypto qlu-recovery-univalue)

enable_testing()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/selftest.cpp"
  CONTENT "#include <qlu/crypto.h>\nint main() { return qlu::SelfTest() ? 0 : 1; }\n")
add_executable(qlu-keytool-selftest "${CMAKE_CURRENT_BINARY_DIR}/selftest.cpp")
target_link_libraries(qlu-keytool-selftest PRIVATE qlu-recovery-crypto)
add_test(NAME qlu_recovery_native_selftest COMMAND qlu-keytool-selftest)
