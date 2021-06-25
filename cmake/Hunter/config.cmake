hunter_config(Boost
   VERSION ${HUNTER_Boost_VERSION}
   CMAKE_ARGS
      USE_CONFIG_FROM_BOOST=ON
      Boost_USE_STATIC_LIBS=ON
      Boost_NO_BOOST_CMAKE=ON
)

hunter_config(koinos_exception
   URL  "https://github.com/koinos/koinos-exception-cpp/archive/373937ced4b890bc6a8dbdad6452560860a38f5e.tar.gz"
   SHA1 "1dd40d3e733d7a9220adbe64e47e40c0b1079062"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_util
   URL  "https://github.com/koinos/koinos-util-cpp/archive/43280d7adc1f033e42bb2e0d50bb39d31a2dbeaa.tar.gz"
   SHA1 "5be977696aa13be3d87500b486cd9e6cef0f12a9"
)

hunter_config(koinos_log
   URL  "https://github.com/koinos/koinos-log-cpp/archive/5d2d7a185f068f76f80c2335773bfbacdbc3176e.tar.gz"
   SHA1 "d3a58334b7ff3fc24933fad94921a57c3cd2369f"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_types
   URL  "https://github.com/koinos/koinos-types/archive/4c63adec26d12aefd4922a41fd8033af5694d816.tar.gz"
   SHA1 "05eff0cc17fc2fd07c6b531b5dce6a8dbc6570a7"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(libsecp256k1
   URL "https://github.com/soramitsu/soramitsu-libsecp256k1/archive/c7630e1bac638c0f16ee66d4dce7b5c49eecbaa5.tar.gz"
   SHA1 "0534fa8948f279b26fd102905215a56f0ad7fa18"
)
