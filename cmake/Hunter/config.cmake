hunter_config(Boost
   VERSION ${HUNTER_Boost_VERSION}
   CMAKE_ARGS
      USE_CONFIG_FROM_BOOST=ON
      Boost_USE_STATIC_LIBS=ON
      Boost_NO_BOOST_CMAKE=ON
)

hunter_config(koinos_exception
   URL "https://github.com/koinos/koinos-exception-cpp/archive/9ca5339489434afa3439d2ba88879c24f1e35280.tar.gz"
   SHA1 "bfc97555cd9b5193dd96e00d42bc48b3050aec1f"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_util
   URL "https://github.com/koinos/koinos-util-cpp/archive/a5f56e6cc68f150f5a126698c42764fbb04c8505.tar.gz"
   SHA1 "deb309751ff754d62b2de7d1c6a726b19d82f372"
)

hunter_config(koinos_log
   URL  "https://github.com/koinos/koinos-log-cpp/archive/4ecb8399d05d1639c52a34845f55aa826f35d484.tar.gz"
   SHA1 "1b11e2acadd4d37a483944096bed916ba579637d"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_types
   URL "https://github.com/koinos/koinos-types/archive/d8a9db91761d8aa84723f0b0b5b12e032fad9fa9.tar.gz"
   SHA1 "3764a668d7e0f6c5876f522f11bdc39cbdbbba8b"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(libsecp256k1
   URL "https://github.com/soramitsu/soramitsu-libsecp256k1/archive/c7630e1bac638c0f16ee66d4dce7b5c49eecbaa5.tar.gz"
   SHA1 "0534fa8948f279b26fd102905215a56f0ad7fa18"
)

