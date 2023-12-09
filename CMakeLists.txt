
cmake_minimum_required(VERSION 3.19.0)

cmake_policy(SET CMP0074 NEW)
cmake_policy(SET CMP0114 NEW)

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL 3.24.0)
  cmake_policy(SET CMP0135 NEW)
endif()

if(${CMAKE_VERSION} VERSION_GREATER_EQUAL 3.27.0)
  cmake_policy(SET CMP0144 NEW)
endif()

include(FetchContent)
FetchContent_Declare(
  koinos_cmake
  GIT_REPOSITORY https://github.com/koinos/koinos-cmake.git
  GIT_TAG        5b72b0805bb6770d1c1462bcdf9ff0e423a5dd2c
)
FetchContent_MakeAvailable(koinos_cmake)

include("${koinos_cmake_SOURCE_DIR}/Koinos.cmake")

project(koinos_crypto
  VERSION 1.0.1
  DESCRIPTION "The Koinos cryptography library"
  LANGUAGES CXX C)

koinos_define_version()

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

add_subdirectory(src)
add_subdirectory(tests)
