hunter_config(Boost
   VERSION ${HUNTER_Boost_VERSION}
   CMAKE_ARGS
      USE_CONFIG_FROM_BOOST=ON
      Boost_USE_STATIC_LIBS=ON
      Boost_NO_BOOST_CMAKE=ON
)

hunter_config(Protobuf
   VERSION ${HUNTER_Protobuf_VERSION}
   CMAKE_ARGS
      CMAKE_CXX_FLAGS=-fvisibility=hidden
      CMAKE_C_FLAGS=-fvisibility=hidden
)

hunter_config(koinos_log
   URL  "https://github.com/koinos/koinos-log-cpp/archive/8a148b2839116e060b3327fe6358210dd2a55f4d.tar.gz"
   SHA1 "8075e5882ffc5d450b35521792dcf6b29027cebd"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_util
   URL  "https://github.com/koinos/koinos-util-cpp/archive/cb6e5eadfb06dd0274e5d4ba8c9189909d529071.tar.gz"
   SHA1 "e420b0f572fec7c9c379a788c7e485e7b84b4d65"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_exception
   URL  "https://github.com/koinos/koinos-exception-cpp/archive/071924986460c492d98b14d108d64da8d83c4593.tar.gz"
   SHA1 "5b7af085047be840e3894e55fee68a852866661f"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_proto
   URL  "https://github.com/koinos/koinos-proto-cpp/archive/4acb3322d25148c66cf423cbe1c77c202439dfa8.tar.gz"
   SHA1 "b8df692d6a535105c7673c883f0b3b8db5732d13"
)

hunter_config(libsecp256k1
   URL "https://github.com/soramitsu/soramitsu-libsecp256k1/archive/c7630e1bac638c0f16ee66d4dce7b5c49eecbaa5.tar.gz"
   SHA1 "0534fa8948f279b26fd102905215a56f0ad7fa18"
)
