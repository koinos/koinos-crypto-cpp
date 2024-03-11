
cmake_minimum_required(VERSION 3.19.0)

cmake_policy(VERSION 3.19.0...3.27.4)

include(FetchContent)
FetchContent_Declare(
  koinos_cmake
  GIT_REPOSITORY https://github.com/koinos/koinos-cmake.git
  GIT_TAG        0c8433a118eb4cd5a86bb7ac4708a38db8166801)
FetchContent_MakeAvailable(koinos_cmake)

include("${koinos_cmake_SOURCE_DIR}/Koinos.cmake")

project(koinos_crypto
  VERSION 1.0.1
  DESCRIPTION "The Koinos cryptography library"
  LANGUAGES CXX C)

koinos_define_version()

koinos_add_package(Boost CONFIG REQUIRED
  ADD_COMPONENTS log exception program_options test
  FIND_COMPONENTS log log_setup exception program_options
)

koinos_add_package(yaml-cpp CONFIG REQUIRED)
koinos_add_package(OpenSSL REQUIRED)
koinos_add_package(ethash CONFIG REQUIRED)
koinos_add_package(nlohmann_json CONFIG REQUIRED)
koinos_add_package(libsecp256k1-vrf CONFIG REQUIRED)
koinos_add_package(Protobuf CONFIG REQUIRED)
koinos_add_package(gRPC CONFIG REQUIRED)

koinos_add_package(koinos_proto CONFIG REQUIRED)
koinos_add_package(koinos_exception CONFIG REQUIRED)
koinos_add_package(koinos_log CONFIG REQUIRED)
koinos_add_package(koinos_util CONFIG REQUIRED)

add_subdirectory(src)
add_subdirectory(tests)
