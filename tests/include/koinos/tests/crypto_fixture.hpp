#pragma once
#include <koinos/crypto/multihash.hpp>
#include <koinos/pack/classes.hpp>

#include <iostream>

using nlohmann::json;

// SHA test vectors taken from http://www.di-mgt.com.au/sha_testvectors.html
static const std::string TEST1("abc");
static const std::string TEST2("");
static const std::string TEST3("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
static const std::string TEST4("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
static char TEST5[1000001];
static const std::string TEST6("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");

static void init_5()
{
   memset( TEST5, 'a', sizeof(TEST5) - 1 );
   TEST5[1000000] = 0;
}

struct crypto_fixture
{
   crypto_fixture()
   {
      init_5();
   }

   template< typename Blob >
   std::string hex_string( const Blob& b )
   {
      static const char hex[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

      std::string s;

      for ( auto c : b )
      {
         s += hex[(c & 0xF0) >> 4];
         s += hex[c & 0x0F];
      }

      return s;
   }

   void test( uint64_t code, const std::string& to_hash, const std::string& expected )
   {
      koinos::multihash mh1 = koinos::crypto::hash_str( code, to_hash.c_str(), to_hash.size() );
      BOOST_CHECK_EQUAL( expected, hex_string( mh1.digest ) );
      BOOST_CHECK_EQUAL( code, mh1.id );
      BOOST_CHECK_EQUAL( koinos::crypto::multihash_standard_size( code ), mh1.digest.size() );
   }

   void test_big( uint64_t code, const std::string& expected )
   {
      koinos::crypto::encoder enc( code );
      for (char c : TEST6) { enc.put(c); }
      for (int i = 0; i < 16777215; i++) {
         enc.write( TEST6.c_str(), TEST6.size() );
      }
      koinos::multihash mh1;
      enc.get_result( mh1 );
      BOOST_CHECK_EQUAL( expected, hex_string( mh1.digest ) );
      BOOST_CHECK_EQUAL( code, mh1.id );
      BOOST_CHECK_EQUAL( koinos::crypto::multihash_standard_size( code ), mh1.digest.size() );
   }
};
