add_library(crypto
  elliptic.cpp
  multihash.cpp
  openssl.cpp
  include/koinos/crypto/elliptic.hpp
  include/koinos/crypto/merkle_tree.hpp
  include/koinos/crypto/multihash.hpp
  include/koinos/crypto/openssl.hpp)

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
      ethash::ethash)

target_include_directories(
  crypto
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

add_library(Koinos::crypto ALIAS crypto)

install(
  FILES
    include/koinos/crypto/elliptic.hpp
    include/koinos/crypto/merkle_tree.hpp
    include/koinos/crypto/multihash.hpp
    include/koinos/crypto/openssl.hpp
  DESTINATION
    "include/koinos/crypto")
