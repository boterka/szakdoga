cmake_minimum_required(VERSION 3.16)
project(feistel C)

set(OQS ${CMAKE_SOURCE_DIR}/../liboqs/build)

# GLOB_RECURSE: az alkönyvtárakban lévő KEM-ek (pl. src/FrodoKem/*.c) is forduljanak
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.c)
add_executable(feistel ${SOURCES})

target_include_directories(feistel PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OQS}/include)
# Statikusan linkelünk: a liboqs.so nem exportálja az OQS_SHA3_* függvényeket
# (csak az OQS_API-val jelölteket), a liboqs.a-ban viszont benne vannak.
# A liboqs OpenSSL-lel épült (OQS_USE_OPENSSL), ezért a libcrypto is kell.
find_package(OpenSSL REQUIRED)
target_link_libraries(feistel PRIVATE ${OQS}/lib/liboqs.a OpenSSL::Crypto)
target_compile_options(feistel PRIVATE -Wall -O3 -fopt-info-vec)
