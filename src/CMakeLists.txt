add_library(crypto
  elliptic.cpp
  multihash.cpp
  openssl.cpp

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

koinos_add_format_target(crypto)


target_include_directories(
  crypto
    PUBLIC
      $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

add_library(Koinos::crypto ALIAS crypto)

install(
  DIRECTORY
    ${PROJECT_SOURCE_DIR}/include
  DESTINATION
    include/
)
