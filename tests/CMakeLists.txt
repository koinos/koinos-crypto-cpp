include(CTest)

enable_testing()

file(GLOB UNIT_TESTS "tests/*.cpp")
file(GLOB_RECURSE TEST_FIXTURES "include/*.hpp")

koinos_parse_unit_tests(TEST_CASES ${UNIT_TESTS})

koinos_add_test(koinos_crypto_tests
   SOURCES ${UNIT_TESTS} ${TEST_FIXTURES}
   TESTS ${TEST_CASES}
)

target_link_libraries(koinos_crypto_tests Koinos::crypto ${PLATFORM_SPECIFIC_LIBS})
target_include_directories(koinos_crypto_tests PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
