file(GLOB HEADERS "include/koinos/crypto/*.hpp")
add_library(koinos_crypto
            elliptic.cpp
            multihash.cpp
            openssl.cpp
            ${HEADERS})

target_link_libraries(koinos_crypto PUBLIC Koinos::exception Koinos::proto Koinos::util OpenSSL::SSL OpenSSL::Crypto secp256k1-vrf::secp256k1-vrf protobuf::libprotobuf ethash::ethash)

target_include_directories(koinos_crypto PUBLIC
   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
   $<INSTALL_INTERFACE:include>
)

add_library(Koinos::crypto ALIAS koinos_crypto)

install(FILES ${HEADERS} DESTINATION "include/koinos/crypto")

export(
   TARGETS ${KOINOS_LIB_TARGET_NAME}
   NAMESPACE Koinos::
   FILE ${KOINOS_LIB_CMAKE_PROJECT_TARGETS_FILE}
)

install(
   TARGETS ${KOINOS_LIB_TARGET_NAME}
   EXPORT ${KOINOS_LIB_TARGETS_EXPORT_NAME}
   INCLUDES DESTINATION ${KOINOS_LIB_INCLUDE_INSTALL_DIR}
   RUNTIME DESTINATION bin
   LIBRARY DESTINATION lib
   ARCHIVE DESTINATION lib
)

install(
   EXPORT ${KOINOS_LIB_TARGETS_EXPORT_NAME}
   NAMESPACE Koinos::
   DESTINATION ${KOINOS_LIB_CONFIG_INSTALL_DIR}
)
