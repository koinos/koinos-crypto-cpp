hunter_config(Boost
   VERSION ${HUNTER_Boost_VERSION}
   CMAKE_ARGS
      USE_CONFIG_FROM_BOOST=ON
      Boost_USE_STATIC_LIBS=ON
      Boost_NO_BOOST_CMAKE=ON
)

hunter_config(Protobuf
   URL  "https://github.com/koinos/protobuf/archive/e1b1477875a8b022903b548eb144f2c7bf4d9561.tar.gz"
   SHA1 "5796707a98eec15ffb3ad86ff50e8eec5fa65e68"
   CMAKE_ARGS
      CMAKE_CXX_FLAGS=-fvisibility=hidden
      CMAKE_C_FLAGS=-fvisibility=hidden
)

hunter_config(yaml-cpp
   VERSION "0.6.3"
   CMAKE_ARGS
      CMAKE_CXX_FLAGS=-fvisibility=hidden
      CMAKE_C_FLAGS=-fvisibility=hidden
)

hunter_config(koinos_log
   URL  "https://github.com/koinos/koinos-log-cpp/archive/36dd30f44c61489fb9e8fb5a1e6c245f872d0350.tar.gz"
   SHA1 "1a194b8d2fcfe8101fcd72fa97764940ade3466c"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_util
   URL  "https://github.com/koinos/koinos-util-cpp/archive/86730d4bde45021921b087a5c0d19a01056939d7.tar.gz"
   SHA1 "8c2cc5f7f25e95a1083d4a184243e6c054a0d9ba"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_exception
   URL  "https://github.com/koinos/koinos-exception-cpp/archive/1f7513664dc5a63fffb4ca576a35295ac6778d98.tar.gz"
   SHA1 "791c28682e0f8c7295abc3693e978a209a15f18c"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_proto
   URL  "https://github.com/koinos/koinos-proto-cpp/archive/5e93d9f313ea759eb8b2515e10a25160aa2b1db0.tar.gz"
   SHA1 "11b9724202986f488185fe3d6d232a386c0319b7"
)

hunter_config(libsecp256k1
   URL "https://github.com/soramitsu/soramitsu-libsecp256k1/archive/c7630e1bac638c0f16ee66d4dce7b5c49eecbaa5.tar.gz"
   SHA1 "0534fa8948f279b26fd102905215a56f0ad7fa18"
)
