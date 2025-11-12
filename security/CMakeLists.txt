cmake_minimum_required(VERSION 3.15)

project(bedrock C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BEDROCK_USE_OPENSSL "Prefer OpenSSL when available (non-Apple, non-Windows)" ON)
option(BEDROCK_ENABLE_SPHINCS "Enable SPHINCS+ SHA2-128s support via external backend" OFF)

include(GNUInstallDirs)

# Detect platforms and dependencies
set(BEDROCK_PLATFORM "FALLBACK")
set(BEDROCK_LINK_LIBS "")

if (APPLE)
  set(BEDROCK_PLATFORM "COMMONCRYPTO")
  add_compile_definitions(BEDROCK_USE_COMMONCRYPTO)
elseif (WIN32)
  set(BEDROCK_PLATFORM "BCRYPT")
  add_compile_definitions(BEDROCK_USE_BCRYPT)
  list(APPEND BEDROCK_LINK_LIBS bcrypt)
elseif (BEDROCK_USE_OPENSSL)
  find_package(OpenSSL COMPONENTS Crypto)
  if (OpenSSL_FOUND)
    set(BEDROCK_PLATFORM "OPENSSL")
    add_compile_definitions(BEDROCK_USE_OPENSSL)
    list(APPEND BEDROCK_LINK_LIBS OpenSSL::Crypto)
  endif()
endif()

message(STATUS "bedrock backend: ${BEDROCK_PLATFORM}")

add_library(bedrock STATIC
  bedrock/bedrock.c
  bedrock/sha256_fallback.c
  bedrock/sha512_fallback.c
  bedrock/prng.c
  bedrock/sphincs_sha2_128s.c
  bedrock/p521_field.c
  bedrock/p521_scalar.c
  bedrock/p521_ec.c
  bedrock/p521_ecies.c
  bedrock/aead.c
  bedrock/p521_ecdsa.c
)

target_include_directories(bedrock PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bedrock)
target_link_libraries(bedrock PUBLIC ${BEDROCK_LINK_LIBS})

add_executable(bedrock_example examples/bedrock_example.c)
target_link_libraries(bedrock_example PRIVATE bedrock)

add_executable(bedrock_tests tests/test_bedrock.c)
target_link_libraries(bedrock_tests PRIVATE bedrock)

enable_testing()
add_test(NAME bedrock_tests COMMAND bedrock_tests)

add_executable(bedrock_prng_tests tests/test_prng.c)
target_link_libraries(bedrock_prng_tests PRIVATE bedrock)
add_test(NAME bedrock_prng_tests COMMAND bedrock_prng_tests)

add_executable(bedrock_aead_tests tests/test_aead.c)
target_link_libraries(bedrock_aead_tests PRIVATE bedrock)
add_test(NAME bedrock_aead_tests COMMAND bedrock_aead_tests)

add_executable(bedrock_aead512_tests tests/test_aead512.c)
target_link_libraries(bedrock_aead512_tests PRIVATE bedrock)
add_test(NAME bedrock_aead512_tests COMMAND bedrock_aead512_tests)

add_executable(bedrock_p521_ecdsa_tests tests/test_p521_ecdsa.c)
target_link_libraries(bedrock_p521_ecdsa_tests PRIVATE bedrock)
add_test(NAME bedrock_p521_ecdsa_tests COMMAND bedrock_p521_ecdsa_tests)

add_executable(bedrock_p521_field_tests tests/test_p521_field.c)
target_link_libraries(bedrock_p521_field_tests PRIVATE bedrock)
add_test(NAME bedrock_p521_field_tests COMMAND bedrock_p521_field_tests)

add_executable(bedrock_p521_ecies_tests tests/test_p521_ecies.c)
target_link_libraries(bedrock_p521_ecies_tests PRIVATE bedrock)
add_test(NAME bedrock_p521_ecies_tests COMMAND bedrock_p521_ecies_tests)
add_executable(bedrock_sphincs_tests tests/test_sphincs.c)
target_link_libraries(bedrock_sphincs_tests PRIVATE bedrock)
add_test(NAME bedrock_sphincs_tests COMMAND bedrock_sphincs_tests)
install(TARGETS bedrock ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES bedrock/bedrock.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})


