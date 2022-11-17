#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <deque>
#include <iostream>
#include <iterator>
#include <list>
#include <sstream>
#include <vector>

#include <koinos/bigint.hpp>

#include <koinos/util/base58.hpp>
#include <koinos/util/conversion.hpp>
#include <koinos/util/hex.hpp>

#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/crypto/merkle_tree.hpp>

#include <koinos/common.pb.h>

#include <koinos/tests/crypto_fixture.hpp>

using namespace koinos::crypto;
using namespace std::string_literals;

BOOST_FIXTURE_TEST_SUITE( crypto_tests, crypto_fixture )

BOOST_AUTO_TEST_CASE( key_test )
{
   auto priv = private_key::regenerate( hash( multicodec::sha2_256, std::string{ "seed" } ) );
   auto pub = priv.get_public_key();
   auto compressed = pub.serialize();
   auto pub2 = public_key::deserialize( compressed );
   BOOST_REQUIRE_EQUAL( pub.to_address_bytes(), pub2.to_address_bytes() );

   std::stringstream ss;
   koinos::to_binary( ss, pub );
   public_key pub3;
   koinos::from_binary( ss, pub3 );
   BOOST_REQUIRE_EQUAL( pub.to_address_bytes(), pub3.to_address_bytes() );
}

BOOST_AUTO_TEST_CASE( ripemd160_test )
{
   test( multicodec::ripemd_160, TEST1, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" );
   test( multicodec::ripemd_160, TEST2, "9c1185a5c5e9fc54612808977ee8f548b2258d31" );
   test( multicodec::ripemd_160, TEST3, "12a053384a9c0c88e405a06c27dcf49ada62eb2b" );
   test( multicodec::ripemd_160, TEST4, "6f3fa39b6b503c384f919a49a7aa5c2c08bdfb45" );
   test( multicodec::ripemd_160, TEST5, "52783243c1697bdbe16d37f97f68f08325dc1528" );
   test_big( multicodec::ripemd_160, "29b6df855772aa9a95442bf83b282b495f9f6541" );
}

BOOST_AUTO_TEST_CASE( sha1_test )
{
   test( multicodec::sha1, TEST1, "a9993e364706816aba3e25717850c26c9cd0d89d" );
   test( multicodec::sha1, TEST2, "da39a3ee5e6b4b0d3255bfef95601890afd80709" );
   test( multicodec::sha1, TEST3, "84983e441c3bd26ebaae4aa1f95129e5e54670f1" );
   test( multicodec::sha1, TEST4, "a49b2446a02c645bf419f995b67091253a04a259" );
   test( multicodec::sha1, TEST5, "34aa973cd4c4daa4f61eeb2bdbad27316534016f" );
   test_big( multicodec::sha1, "7789f0c9ef7bfc40d93311143dfbe69e2017f592" );
}

BOOST_AUTO_TEST_CASE( sha256_test )
{
   test( multicodec::sha2_256, TEST1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" );
   test( multicodec::sha2_256, TEST2, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" );
   test( multicodec::sha2_256, TEST3, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" );
   test( multicodec::sha2_256, TEST4, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" );
   test( multicodec::sha2_256, TEST5, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" );
   test_big( multicodec::sha2_256, "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e" );
}

BOOST_AUTO_TEST_CASE( sha512_test )
{
   test( multicodec::sha2_512, TEST1, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" );
   test( multicodec::sha2_512, TEST2, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" );
   test( multicodec::sha2_512, TEST3, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
                           "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" );
   test( multicodec::sha2_512, TEST4, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                           "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" );
   test( multicodec::sha2_512, TEST5, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                           "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" );
   test_big( multicodec::sha2_512, "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d"
                        "77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086" );
}

BOOST_AUTO_TEST_CASE( keccak_256_test )
{
   auto eh = koinos::crypto::multihash::empty( koinos::crypto::multicodec::keccak_256 );
   BOOST_CHECK_EQUAL( koinos::util::to_hex( eh.digest() ), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" );

   auto h1 = koinos::crypto::hash( koinos::crypto::multicodec::keccak_256, koinos::util::from_hex< std::string >( "0x20ff454369a5d05b81a78f3db05819fea9b08c2384f75cb0ab6aa115dd690da3131874a1ca8f708ad1519ea952c1e249cb540d196392c79e87755424fee7c890808c562722359eea52e8a12fbbb969dd7961d2ba52037493755a5fa04f0d50a1aa26c9b44148c0d3b94d1c4a59a31aca15ae8bd44acb7833d8e91c4b86fa3135a423387b8151b4133ed23f6d7187b50ec2204ad901ad74d396e44274e0ecafaae17b3b9085e22260b35ca53b15cc52abba758af6798fbd04eceeced648f3af4fdb3ded7557a9a5cfb7382612a8a8f3f45947d1a29ce29072928ec193ca25d51071bd5e1984ecf402f306ea762f0f25282f5296d997658be3f983696ffa6d095c6369b4daf79e9a5d3136229128f8eb63c12b9e9fa78aff7a3e9e19a62022493cd136defbb5bb7ba1b938f367fd2f63eb5ca76c0b0ff21b9e36c3f07230cf3c3074e5da587040a76975d7e39f4494ace5486fcbf380ab7558c4fe89656335b82e4db8659509eab46a19613126e594042732dd4c411f41aa8cdeac71c0fb40a94e6da558c05e77b6182806f26d9afdf3da00c69419222c8186a6efad600b410e6ce2f2a797e49dc1f135319801fa6f396b06f975e2a190a023e474b618e7" ) );
   BOOST_CHECK_EQUAL( koinos::util::to_hex( h1.digest() ), "0x0ec8d9d20ddf0a7b0251e941a7261b557507ff6287b504362a8f1734c5a91012" );

   auto h2 = koinos::crypto::hash( koinos::crypto::multicodec::keccak_256, koinos::util::from_hex< std::string >( "0x4fbdc596508d24a2a0010e140980b809fb9c6d55ec75125891dd985d37665bd80f9beb6a50207588abf3ceee8c77cd8a5ad48a9e0aa074ed388738362496d2fb2c87543bb3349ea64997ce3e7b424ea92d122f57dbb0855a803058437fe08afb0c8b5e7179b9044bbf4d81a7163b3139e30888b536b0f957eff99a7162f4ca5aa756a4a982dfadbf31ef255083c4b5c6c1b99a107d7d3afffdb89147c2cc4c9a2643f478e5e2d393aea37b4c7cb4b5e97dadcf16b6b50aae0f3b549ece47746db6ce6f67dd4406cd4e75595d5103d13f9dfa79372924d328f8dd1fcbeb5a8e2e8bf4c76de08e3fc46aa021f989c49329c7acac5a688556d7bcbcb2a5d4be69d3284e9c40ec4838ee8592120ce20a0b635ecadaa84fd5690509f54f77e35a417c584648bc9839b974e07bfab0038e90295d0b13902530a830d1c2bdd53f1f9c9faed43ca4eed0a8dd761bc7edbdda28a287c60cd42af5f9c758e5c7250231c09a582563689afc65e2b79a7a2b68200667752e9101746f03184e2399e4ed8835cb8e9ae90e296af220ae234259fe0bd0bcc60f7a4a5ff3f70c5ed4de9c8c519a10e962f673c82c5e9351786a8a3bfd570031857bd4c87f4fca31ed4d50e14f2107da02cb5058700b74ea241a8b41d78461658f1b2b90bfd84a4c2c9d6543861ab3c56451757dcfb9ba60333488dbdd02d601b41aae317ca7474eb6e6dd" ) );
   BOOST_CHECK_EQUAL( koinos::util::to_hex( h2.digest() ), "0x0ea33e2e34f572440640244c7f1f5f04697ce97139bda72a6558d8663c02b388" );
}

BOOST_AUTO_TEST_CASE( ecc )
{
   private_key nullkey;
   std::string pass = "foobar";

   for( uint32_t i = 0; i < 100; ++ i )
   {
      multihash h = hash( multicodec::sha2_256, pass.c_str(), pass.size() );
      private_key priv = private_key::regenerate( h );
      BOOST_CHECK( nullkey != priv );
      public_key pub = priv.get_public_key();

      pass += "1";
      multihash h2 = hash( multicodec::sha2_256, pass.c_str(), pass.size() );
      public_key  pub1  = pub.add( h2 );
      private_key priv1 = private_key::generate_from_seed(h, h2);

      auto sig = priv.sign_compact( h );
      auto recover = public_key::recover( sig, h );
      BOOST_CHECK( recover == pub );
   }
}

BOOST_AUTO_TEST_CASE( private_wif )
{
   std::string secret = "foobar";
   std::string wif = "5KJTiKfLEzvFuowRMJqDZnSExxxwspVni1G4RcggoPtDqP5XgM1";
   std::string compressed_wif = "L3n4uPNBvne4p6BCUdhpThYQe21wDJe4jz9U7eWAfn15e9tj2jAF";
   private_key key1 = private_key::regenerate( hash( multicodec::sha2_256, secret.c_str(), secret.size() ) );
   BOOST_CHECK_EQUAL( key1.to_wif(), compressed_wif );

   private_key key2 = private_key::from_wif( wif );
   BOOST_CHECK( key1 == key2 );

   // Encoding:
   // Prefix Secret                                                           Checksum
   // 80     C3AB8FF13720E8AD9047DD39466B3C8974E592C2FA383D4A3960714CAEF0C4F2 C957BEB4

   // Wrong checksum, change last octal (4->3)
   wif = "5KJTiKfLEzvFuowRMJqDZnSExxxwspVni1G4RcggoPtDqP5XgLz";
   BOOST_REQUIRE_THROW( private_key::from_wif( wif ), key_serialization_error );

   // Wrong seed, change first octal of secret (C->D)
   wif = "5KRWQqW5riLTcB39nLw6K7iv2HWBMYvbP7Ch4kUgRd8kEvLH5jH";
   BOOST_REQUIRE_THROW( private_key::from_wif( wif ), key_serialization_error );

   // Wrong prefix, change first octal of prefix (8->7)
   wif = "4nCYtcUpcC6dkge8r2uEJeqrK97TUZ1n7n8LXDgLtun1wRyxU2P";
   BOOST_REQUIRE_THROW( private_key::from_wif( wif ), key_serialization_error );
}

BOOST_AUTO_TEST_CASE( public_address )
{
   std::string private_wif = "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V";
   auto priv_key = private_key::from_wif( private_wif );
   auto pub_key = priv_key.get_public_key();
   auto address = pub_key.to_address_bytes();

   const unsigned char bytes[] = { 0x00, 0xf5, 0x4a, 0x58, 0x51, 0xe9, 0x37, 0x2b, 0x87, 0x81, 0x0a, 0x8e, 0x60,
                          0xcd, 0xd2, 0xe7, 0xcf, 0xd8, 0x0b, 0x6e, 0x31, 0xc7, 0xf1, 0x8f, 0xe8 };
   std::string address_bytes( reinterpret_cast< const char* >( bytes ), sizeof( bytes ) );

   BOOST_REQUIRE_EQUAL( address, address_bytes );
}

BOOST_AUTO_TEST_CASE( compressed_key )
{
   std::string uncompressed_wif = "5JtU2c2MHKb8xSeNvsZJpxZRXeRg6iq6uwc6EUtDA9zsWM6B4c5";
   auto priv_key = private_key::from_wif( uncompressed_wif );

   std::string expected_wif = "L1xAJ5axX33g7iBynn9bggE7GGBuaFdK6g1t6W52fQiRvQi73evQ";
   BOOST_CHECK_EQUAL( priv_key.to_wif(), expected_wif );

   std::string expected_address = "13Sqw4TrwdZ8RZ9UVfqqA2i3mrbeumcWba";
   BOOST_CHECK_EQUAL( koinos::util::to_base58( priv_key.get_public_key().to_address_bytes() ), expected_address );

   priv_key = private_key::from_wif( expected_wif );
   BOOST_CHECK_EQUAL( priv_key.to_wif(), expected_wif );
   BOOST_CHECK_EQUAL( koinos::util::to_base58( priv_key.get_public_key().to_address_bytes() ), expected_address );
}

BOOST_AUTO_TEST_CASE( zerohash )
{
   multihash mh;
   mh = multihash::zero( multicodec::sha2_256 );
   BOOST_CHECK( mh.code() == multicodec::sha2_256 );
   BOOST_CHECK( mh.digest().size() == 256/8 );

   mh = multihash::zero( multicodec::ripemd_160 );
   BOOST_CHECK( mh.code() == multicodec::ripemd_160 );
   BOOST_CHECK( mh.digest().size() == 160/8 );
}

BOOST_AUTO_TEST_CASE( emptyhash )
{
   multihash mh = multihash::empty( multicodec::sha2_256 );
   BOOST_CHECK_EQUAL( "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex_string( mh.digest() ) );
}

BOOST_AUTO_TEST_CASE( merkle )
{
   std::vector< std::string > values
   {
      "the", "quick", "brown", "fox", "jumps", "over", "a", "lazy", "dog"
   };

   std::vector< std::string > wh_hex
   {
      "b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0",
      "22c72aa82ce77c82e2ca65a711c79eaa4b51c57f85f91489ceeacc7b385943ba",
      "5eb67f9f8409b9c3f739735633cbdf92121393d0e13bd0f464b1b2a6a15ad2dc",
      "776cb326ab0cd5f0a974c1b9606044d8485201f2db19cf8e3749bdee5f36e200",
      "ef30940a2d1b943c8007b8a15e45935dc01902b7c0534dc7e27fda30a9b81aef",
      "5fb6a47e368e12e5d8b19280796e6a3d146fe391ed2e967d5f95c55bfb0f9c2f",
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "81fd67d02f679b818a4df6a50139958aa857eddc4d8f3561630dfb905e6d3c24",
      "cd6357efdd966de8c0cb2f876cc89ec74ce35f0968e11743987084bd42fb8944"
   };

   auto h = [&]( const multihash& ha, const multihash& hb ) -> multihash
   {
      std::vector< std::byte > temp;
      std::copy( ha.digest().begin(), ha.digest().end(), std::back_inserter( temp ) );
      std::copy( hb.digest().begin(), hb.digest().end(), std::back_inserter( temp ) );
      multihash result = hash( multicodec::sha2_256, (char*)temp.data(), temp.size() );
      return result;
   };

   // Hash of each word
   std::vector< multihash > wh;
   for( size_t i = 0; i < values.size(); i++ )
   {
      wh.push_back( hash( multicodec::sha2_256, values[i].c_str(), values[i].size() ) );
      BOOST_CHECK_EQUAL( wh_hex[i], hex_string( wh[i].digest() ) );
   }

   const std::string n01        = "0020397085ab4494829e691c49353a04d3201fda20c6a8a6866cf0f84bb8ce47";
   const std::string n23        = "78d4e37706320c82b2dd092eeb04b1f271523f86f910bf680ff9afcb2f8a33e1";
   const std::string n0123      = "e07aa684d91ffcbb89952f5e99b6181f7ee7bd88bd97be1345fc508f1062c050";
   const std::string n45        = "4185f41c5d7980ae7d14ce248f50e2854826c383671cf1ee3825ea957315c627";
   const std::string n67        = "b2a6704395c45ad8c99247103b580f7e7a37f06c3d38075ce4b02bc34c6a6754";
   const std::string n4567      = "2f24a249901ee8392ba0bb3b90c8efd6e2fee6530f45769199ef82d0b091d8ba";
   const std::string n01234567  = "913b7dce068efc8db6fab0173481f137ce91352b341855a1719aaff926169987";
   const std::string n8         = "cd6357efdd966de8c0cb2f876cc89ec74ce35f0968e11743987084bd42fb8944";
   const std::string n012345678 = "e24e552e0b6cf8835af179a14a766fb58c23e4ee1f7c6317d57ce39cc578cfac";

   multihash h01        = h( wh[0], wh[1] );
   multihash h23        = h( wh[2], wh[3] );
   multihash h0123      = h( h01, h23 );
   multihash h45        = h( wh[4], wh[5] );
   multihash h67        = h( wh[6], wh[7] );
   multihash h4567      = h( h45, h67 );
   multihash h01234567  = h( h0123, h4567 );
   multihash h8         = wh[8];
   multihash h012345678 = h( h01234567, h8 );

   BOOST_CHECK_EQUAL( n01       , hex_string(        h01.digest() ) );
   BOOST_CHECK_EQUAL( n23       , hex_string(        h23.digest() ) );
   BOOST_CHECK_EQUAL( n0123     , hex_string(      h0123.digest() ) );
   BOOST_CHECK_EQUAL( n45       , hex_string(        h45.digest() ) );
   BOOST_CHECK_EQUAL( n67       , hex_string(        h67.digest() ) );
   BOOST_CHECK_EQUAL( n4567     , hex_string(      h4567.digest() ) );
   BOOST_CHECK_EQUAL( n01234567 , hex_string(  h01234567.digest() ) );
   BOOST_CHECK_EQUAL( n012345678, hex_string( h012345678.digest() ) );

   auto tree = merkle_tree( multicodec::sha2_256, values );
   BOOST_CHECK_EQUAL( n012345678, hex_string( tree.root()->hash().digest() ) );

   BOOST_CHECK_EQUAL( *tree.root()->left()->left()->left()->left()->value()   , values[0] ); // the
   BOOST_CHECK_EQUAL( *tree.root()->left()->left()->left()->right()->value()  , values[1] ); // quick
   BOOST_CHECK_EQUAL( *tree.root()->left()->left()->right()->left()->value()  , values[2] ); // brown
   BOOST_CHECK_EQUAL( *tree.root()->left()->left()->right()->right()->value() , values[3] ); // fox
   BOOST_CHECK_EQUAL( *tree.root()->left()->right()->left()->left()->value()  , values[4] ); // jumps
   BOOST_CHECK_EQUAL( *tree.root()->left()->right()->left()->right()->value() , values[5] ); // over
   BOOST_CHECK_EQUAL( *tree.root()->left()->right()->right()->left()->value() , values[6] ); // a
   BOOST_CHECK_EQUAL( *tree.root()->left()->right()->right()->right()->value(), values[7] ); // lazy
   BOOST_CHECK_EQUAL( *tree.root()->right()->value()                          , values[8] ); // dog

   std::vector< multihash > v( values.size() );
   std::transform(
      std::begin( values ),
      std::end( values ),
      std::begin( v ),
      [] ( const std::string& s ) { return hash( multicodec::sha2_256, s ); }
   );

   auto multihash_tree = merkle_tree( multicodec::sha2_256, v );
   BOOST_CHECK_EQUAL( multihash_tree.root()->hash(), tree.root()->hash() );

   auto mtree = merkle_tree( multicodec::sha2_256, std::vector< std::string >() );
   BOOST_CHECK( mtree.root()->hash() == multihash::empty( multicodec::sha2_256 ) );
   BOOST_CHECK( mtree.root()->hash() != multihash::zero( multicodec::sha2_256 ) );
}

BOOST_AUTO_TEST_CASE( protocol_buffers_test )
{
   std::string id_str = "id";
   std::string previous_str = "previous";

   koinos::block_topology block_topology;
   block_topology.set_height( 100 );
   block_topology.set_id( koinos::util::converter::as< std::string>( hash( multicodec::sha1, id_str ) ) );
   block_topology.set_previous( koinos::util::converter::as< std::string>( hash( multicodec::sha2_512, previous_str ) ) );

   auto mhash = hash( multicodec::sha2_256, block_topology );

   std::stringstream stream;
   block_topology.SerializeToOstream( &stream );
   std::string str = stream.str();

   std::vector< std::byte > bytes( str.size() );
   std::transform( str.begin(), str.end(), bytes.begin(), []( char c ) { return std::byte( c ); } );

   BOOST_CHECK( hash( multicodec::sha2_256, bytes ) == mhash );

   auto id_hash = koinos::util::converter::to< multihash >( block_topology.id() );
   BOOST_CHECK( id_hash == hash( multicodec::sha1, id_str ) );

   auto previous_hash = koinos::util::converter::to< multihash >( block_topology.previous() );
   BOOST_CHECK( previous_hash == hash( multicodec::sha2_512, previous_str ) );

   auto mhash2 = hash( multicodec::sha2_256, &block_topology );
   BOOST_CHECK( mhash == mhash2 );
}

BOOST_AUTO_TEST_CASE( multihash_serialization )
{
   auto mhash = hash( multicodec::ripemd_160, std::string( "a quick brown fox jumps over the lazy dog" ) );

   std::stringstream stream;
   koinos::to_binary( stream, mhash );

   multihash tmp;
   koinos::from_binary( stream, tmp );
   BOOST_CHECK( mhash == tmp );

   std::stringstream ss;
   ss << mhash;
   BOOST_CHECK( ss.str() == "0xd3201409c999f213afff19793d8288023c512f71873deb" );

   try {
      KOINOS_THROW( koinos::exception, "test multihash in exception: ${mh}", ("mh", mhash ) );
      BOOST_REQUIRE( false );
   }
   catch( const koinos::exception& e )
   {
      BOOST_REQUIRE( e.what() == std::string( "test multihash in exception: 0xd3201409c999f213afff19793d8288023c512f71873deb" ) );
   }
}

BOOST_AUTO_TEST_CASE( variadic_hash )
{
   std::string id_str = "id";
   std::string previous_str = "previous";

   koinos::block_topology block_topology;
   block_topology.set_height( 100 );
   block_topology.set_id( koinos::util::converter::as< std::string>( hash( multicodec::sha1, id_str ) ) );
   block_topology.set_previous( koinos::util::converter::as< std::string>( hash( multicodec::sha2_512, previous_str ) ) );

   std::stringstream ss;
   block_topology.SerializeToOstream( &ss );
   ss << "a quick brown fox jumps over the lazy dog";

   koinos::uint256_t x = 0;
   koinos::to_binary( ss, x );

   auto mhash1 = hash( multicodec::ripemd_160, ss.str() );
   auto mhash2 = hash( multicodec::ripemd_160, block_topology, std::string( "a quick brown fox jumps over the lazy dog" ), x );

   BOOST_REQUIRE( mhash1 == mhash2 );
}

BOOST_AUTO_TEST_CASE( vrf_tests )
{
   BOOST_TEST_MESSAGE( "Test prove" );

   std::string msg = "sample";
   auto expected_proof = "0x031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d08748c9fbe6b95d17359707bfb8e8ab0c93ba0c515333adcb8b64f372c535e115ccf66ebf5abe6fadb01b5efb37c0a0ec9";
   auto priv_key = private_key::regenerate( multihash( multicodec::sha2_256, koinos::util::from_hex< digest_type >( "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"s ) ) );
   auto pub_key = priv_key.get_public_key();

   auto [proof, proof_hash] = priv_key.generate_random_proof( msg );

   BOOST_CHECK_EQUAL( koinos::util::to_hex( proof ), expected_proof );

   BOOST_TEST_MESSAGE( "Test verify on invalid proofs" );

   for ( int i = 0; i < proof.size(); i++ )
   {
      auto temp = proof.data()[i];
      if ( temp == 0x00 )
         const_cast< char* >( proof.data() )[i] = 0x01;
      else
         const_cast< char* >( proof.data() )[i] = 0x00;

      BOOST_REQUIRE_THROW( pub_key.verify_random_proof( msg, proof ), vrf_validation_error );

      const_cast< char* >( proof.data() )[ i ] = temp;

      pub_key.verify_random_proof( msg, proof );
   }

   BOOST_TEST_MESSAGE( "Test the same message with different provers" );

   for ( int i = 0; i < 10; i++ )
   {
      auto priv_key = private_key::regenerate( hash( multicodec::sha2_256, i ) );
      auto [proof, hash1] = priv_key.generate_random_proof( msg );
      auto hash2 = priv_key.get_public_key().verify_random_proof( msg, proof );

      BOOST_CHECK_EQUAL( hash1, hash2 );
   }

   BOOST_TEST_MESSAGE( "Test different messages with the same prover" );

   for ( int i = 0; i < 10; i++ )
   {
      auto msg = "message" + std::to_string( i );
      auto [proof, hash1] = priv_key.generate_random_proof( msg );
      auto hash2 = priv_key.get_public_key().verify_random_proof( msg, proof );

      BOOST_CHECK_EQUAL( hash1, hash2 );
   }

   BOOST_TEST_MESSAGE( "Test verify" );

   auto expected_hash = "0x612065e309e937ef46c2ef04d5886b9c6efd2991ac484ec64a9b014366fc5d81";

   pub_key = public_key::deserialize( koinos::util::from_hex< compressed_public_key >( "0x032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645" ) );
   proof = koinos::util::from_hex< std::string >( "0x031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f" );
   proof_hash = pub_key.verify_random_proof( msg, proof );

   BOOST_CHECK_EQUAL( koinos::util::to_hex( proof_hash.digest() ), expected_hash );

   BOOST_TEST_MESSAGE( "Test invalid proof size" );

   proof = koinos::util::from_hex< std::string >( "0x031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b" );
   BOOST_CHECK_THROW( pub_key.verify_random_proof( msg, proof ), vrf_validation_error );

   proof = koinos::util::from_hex< std::string >( "0x031f4dbca087a1972d04a07a779b7df1caa99e0f5db2aa21f3aecc4f9e10e85d0814faa89697b482daa377fb6b4a8b0191a65d34a6d90a8a2461e5db9205d4cf0bb4b2c31b5ef6997a585a9f1a72517b6f00" );
   BOOST_CHECK_THROW( pub_key.verify_random_proof( msg, proof ), vrf_validation_error );
}

BOOST_AUTO_TEST_SUITE_END()
