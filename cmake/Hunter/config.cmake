hunter_config(Boost
   VERSION "1.72.0-p1"
   CMAKE_ARGS
      USE_CONFIG_FROM_BOOST=ON
      Boost_USE_STATIC_LIBS=ON
      Boost_NO_BOOST_CMAKE=ON
)

hunter_config(koinos_exception
   URL  "https://github.com/koinos/koinos-exception-cpp/archive/a9d342a55aeeef28d8ff6eb0dcb7bb19ec8d8899.tar.gz"
   SHA1 "9992dacf963f85208e462fa2a21a4bfa68018f4c"
   CMAKE_ARGS
      BUILD_TESTS=OFF
)

hunter_config(koinos_util
   URL  "https://github.com/koinos/koinos-util-cpp/archive/2316ed57cae22170cca5a759a8b539261ac5a6ab.tar.gz"
   SHA1 "db7b2112c2db1e3366ebdd9f773b997ec27694b9"
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

hunter_config(koinos_proto
   URL  "https://github.com/koinos/koinos-proto-cpp/archive/88124ddca9ad4988dec361f43c91cab83d9611eb.tar.gz"
   SHA1 "e42dd458c99a898827822cc21b74812f2eb120c3"
)

hunter_config(libsecp256k1
   URL "https://github.com/soramitsu/soramitsu-libsecp256k1/archive/c7630e1bac638c0f16ee66d4dce7b5c49eecbaa5.tar.gz"
   SHA1 "0534fa8948f279b26fd102905215a56f0ad7fa18"
)

hunter_config(CapnProto
   VERSION "0.8.0"
   URL "https://capnproto.org/capnproto-c++-0.8.0.tar.gz"
   SHA1 "fbc1c65b32748029f1a09783d3ebe9d496d5fcc4"
)

