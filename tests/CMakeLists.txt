include(CTest)

enable_testing()

koinos_add_test(koinos_crypto_tests
  SOURCES
    crypto_test.cpp
    main.cpp

    include/koinos/tests/crypto_fixture.hpp
)

koinos_add_format_target(koinos_crypto_tests)

target_link_libraries(koinos_crypto_tests Koinos::crypto)
target_include_directories(koinos_crypto_tests PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
