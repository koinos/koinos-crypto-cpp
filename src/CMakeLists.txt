add_library(crypto
  koinos/crypto/elliptic.cpp
  koinos/crypto/multihash.cpp
  koinos/crypto/openssl.cpp

  ${PROJECT_SOURCE_DIR}/include/koinos/crypto/elliptic.hpp
  ${PROJECT_SOURCE_DIR}/include/koinos/crypto/merkle_tree.hpp
  ${PROJECT_SOURCE_DIR}/include/koinos/crypto/multihash.hpp
  ${PROJECT_SOURCE_DIR}/include/koinos/crypto/openssl.hpp)

target_link_libraries(
  crypto
    PUBLIC
      Koinos::exception
      Koinos::proto
      Koinos::util
      OpenSSL::SSL
      OpenSSL::Crypto
      secp256k1-vrf::secp256k1-vrf
      protobuf::libprotobuf
      ethash::ethash
)

target_include_directories(
  crypto
    PUBLIC
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

koinos_add_format(TARGET crypto)

add_library(Koinos::crypto ALIAS crypto)

koinos_install(TARGETS crypto)

install(
  DIRECTORY
    ${PROJECT_SOURCE_DIR}/include
  DESTINATION
    ${CMAKE_INSTALL_PREFIX}
)
