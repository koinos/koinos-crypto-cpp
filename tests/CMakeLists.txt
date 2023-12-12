if (NOT BUILD_TESTING)
  return()
endif()

include(CTest)

koinos_add_test(crypto_tests
  SOURCES
    crypto_test.cpp
    main.cpp

    include/koinos/tests/crypto_fixture.hpp
)

target_link_libraries(crypto_tests PRIVATE Koinos::crypto)

target_include_directories(
  crypto_tests
    PRIVATE
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

koinos_add_format(TARGET crypto_tests)

koinos_coverage(
  EXECUTABLE
    crypto_tests
  EXCLUDE
    "tests/*")
