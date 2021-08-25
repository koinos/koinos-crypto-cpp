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
   URL  "https://github.com/koinos/koinos-util-cpp/archive/45f28c63db205da097cdafe39dd5d49dc67ca183.tar.gz"
   SHA1 "3cd0459d232959c36c5ef7b131a7c636b74de03c"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_exception
   URL  "https://github.com/koinos/koinos-exception-cpp/archive/77f5b1cf0877714d4214bab3a7eeab45ad33df54.tar.gz"
   SHA1 "b974a3ef9133c82d144882ad395754c98ee6333c"
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
