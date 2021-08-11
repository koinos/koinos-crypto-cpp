#pragma once
#include <koinos/crypto/multihash.hpp>

#include <iostream>
#include <sstream>
#include <iomanip>

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
      std::stringstream ss;
      ss << std::hex;

      for( int i = 0 ; i < b.size(); ++i )
         ss << std::setw(2) << std::setfill('0') << (int)b[i];

      return ss.str();
   }

   void test( koinos::crypto::multicodec code, const std::string& to_hash, const std::string& expected )
   {
      koinos::crypto::multihash mh1 = koinos::crypto::hash( code, to_hash.c_str(), to_hash.size() );
      BOOST_CHECK_EQUAL( expected, hex_string( mh1.digest() ) );
      BOOST_CHECK_EQUAL(
         static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( code ),
         static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( mh1.code() )
      );
      BOOST_CHECK_EQUAL( koinos::crypto::multihash::standard_size( code ), mh1.digest().size() );
   }

   void test_big( koinos::crypto::multicodec code, const std::string& expected )
   {
      koinos::crypto::encoder enc( code );
      for (char c : TEST6) { enc.put(c); }
      for (int i = 0; i < 16777215; i++) {
         enc.write( TEST6.c_str(), TEST6.size() );
      }
      koinos::crypto::digest_type digest;
      enc.get_result( digest );
      koinos::crypto::multihash mh1( code, digest );
      BOOST_CHECK_EQUAL( expected, hex_string( mh1.digest() ) );
      BOOST_CHECK_EQUAL(
         static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( code ),
         static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( mh1.code() )
      );
      BOOST_CHECK_EQUAL( koinos::crypto::multihash::standard_size( code ), mh1.digest().size() );
   }
};
