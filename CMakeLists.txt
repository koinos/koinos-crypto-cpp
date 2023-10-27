
cmake_minimum_required(VERSION 3.19.0)

include(cmake/Koinos.cmake)

project(koinos_crypto
  VERSION 1.0.1
  DESCRIPTION "The Koinos cryptography library"
  LANGUAGES CXX C)

koinos_define_version()

koinos_coverage(
  EXECUTABLE
  koinos_crypto_tests
  EXCLUDE
    "tests/*"
)

koinos_add_package(Boost CONFIG REQUIRED
  ADD_COMPONENTS log exception test
  FIND_COMPONENTS log log_setup
)

koinos_add_package(yaml-cpp)
koinos_add_package(OpenSSL REQUIRED)

koinos_add_package(abseil NAME absl CONFIG REQUIRED)

koinos_add_package(ethash CONFIG REQUIRED)
koinos_add_package(nlohmann_json CONFIG REQUIRED)
koinos_add_package(libsecp256k1-vrf CONFIG REQUIRED)
koinos_add_package(Protobuf CONFIG REQUIRED)
koinos_add_package(gRPC CONFIG REQUIRED)
koinos_add_package(re2 CONFIG_REQUIRED)
koinos_add_package(c-ares CONFIG REQUIRED)
koinos_add_package(ZLIB CONFIG REQUIRED)

koinos_add_package(koinos_proto CONFIG REQUIRED)
koinos_add_package(koinos_exception CONFIG REQUIRED)
koinos_add_package(koinos_log CONFIG REQUIRED)
koinos_add_package(koinos_util CONFIG REQUIRED)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(libraries)
add_subdirectory(tests)

export(
  TARGETS crypto
  NAMESPACE Koinos::
  FILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake
)

install(
  TARGETS crypto
  EXPORT ${PROJECT_NAME}-targets
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  EXPORT ${PROJECT_NAME}-targets
  NAMESPACE Koinos::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

configure_package_config_file(
  cmake/project.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
