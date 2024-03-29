#pragma once
#include <koinos/crypto/multihash.hpp>

#include <iomanip>
#include <iostream>
#include <sstream>

using nlohmann::json;

// SHA test vectors taken from http://www.di-mgt.com.au/sha_testvectors.html
static const std::string TEST1( "abc" );
static const std::string TEST2( "" );
static const std::string TEST3( "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" );
static const std::string TEST4(
  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" );
static char TEST5[ 1'000'001 ];
static const std::string TEST6( "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" );

static void init_5()
{
  memset( TEST5, 'a', sizeof( TEST5 ) - 1 );
  TEST5[ 1'000'000 ] = 0;
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

    for( int i = 0; i < b.size(); ++i )
      ss << std::setw( 2 ) << std::setfill( '0' ) << (int)b[ i ];

    return ss.str();
  }

  void test( koinos::crypto::multicodec code, const std::string& to_hash, const std::string& expected )
  {
    koinos::crypto::multihash mh1 = koinos::crypto::hash( code, to_hash.c_str(), to_hash.size() );
    BOOST_CHECK_EQUAL( expected, hex_string( mh1.digest() ) );
    BOOST_CHECK_EQUAL( static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( code ),
                       static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( mh1.code() ) );
    BOOST_CHECK_EQUAL( std::size_t( koinos::crypto::multihash::standard_size( code ) ), mh1.digest().size() );
  }

  void test_big( koinos::crypto::multicodec code, const std::string& expected )
  {
    koinos::crypto::detail::openssl_encoder enc( code );
    for( char c: TEST6 )
    {
      enc.put( c );
    }
    for( int i = 0; i < 16'777'215; i++ )
    {
      enc.write( TEST6.c_str(), TEST6.size() );
    }

    auto mh1 = enc.get_hash();
    BOOST_CHECK_EQUAL( expected, hex_string( mh1.digest() ) );
    BOOST_CHECK_EQUAL( static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( code ),
                       static_cast< std::underlying_type_t< koinos::crypto::multicodec > >( mh1.code() ) );
    BOOST_CHECK_EQUAL( std::size_t( koinos::crypto::multihash::standard_size( code ) ), mh1.digest().size() );
  }
};
