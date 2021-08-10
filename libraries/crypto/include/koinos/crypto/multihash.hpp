#pragma once

#include <cstddef>

#include <openssl/evp.h>

#include <koinos/exception.hpp>

namespace koinos::crypto {

KOINOS_DECLARE_EXCEPTION( unknown_hash_algorithm );
KOINOS_DECLARE_EXCEPTION( multihash_size_mismatch );
KOINOS_DECLARE_EXCEPTION( multihash_size_limit_exceeded );

/*
 * Multicodec IDs for hash algorithms
 * https://github.com/multiformats/multicodec/blob/master/table.csv
 */
enum class multicodec : std::uint64_t
{
   identity   = 0x00,
   sha1       = 0x11,
   sha2_256   = 0x12,
   sha2_512   = 0x13,
   ripemd_160 = 0x1053
};

struct encoder;

class multihash
{
public:
   using digest_type = std::vector< std::byte >;
   friend struct encoder;

   multihash() = default;
   multihash( multicodec code, digest_type digest );

   multicodec           code() const;
   const digest_type&   digest() const;
   bool                 is_zero() const;

   static std::size_t   standard_size( multicodec id );
   static multihash     zero( multicodec id, std::size_t size = 0 );
   static multihash     empty( multicodec id, std::size_t size = 0 );

private:
   multicodec               _code = multicodec::identity;
   std::vector< std::byte > _digest;
};

//inline bool multihash_is_zero( const multihash& mh )
//{
//   return std::all_of( mh.digest.begin(), mh.digest.end(), []( char c ) { return (c == 0); } );
//}
//
//inline uint64_t multihash_standard_size( uint64_t id )
//{
//   switch( id )
//   {
//      case CRYPTO_SHA1_ID:
//         return 20;
//      case CRYPTO_SHA2_256_ID:
//         return 32;
//      case CRYPTO_SHA2_512_ID:
//         return 64;
//      case CRYPTO_RIPEMD160_ID:
//         return 20;
//      default:
//         KOINOS_ASSERT( false, unknown_hash_algorithm, "Unknown hash id ${i}", ("i", id) );
//   }
//}

//constexpr bool multihash_id_is_known( uint64_t id )
//{
//   switch ( id )
//   {
//      case CRYPTO_SHA1_ID:
//      case CRYPTO_SHA2_256_ID:
//      case CRYPTO_SHA2_512_ID:
//      case CRYPTO_RIPEMD160_ID:
//         return true;
//   }
//   return false;
//}

struct encoder
{
   encoder( multicodec code, std::size_t size = 0 );
   ~encoder();

   void write( const char* d, size_t len );
   void put( char c ) { write( &c, 1 ); }
   void reset();
   void get_result( std::vector< std::byte >& v );
   inline void get_result( multihash& mh )
   {
      get_result( mh._digest );
      mh._code = _code;
   }

   private:
      const EVP_MD* md = nullptr;
      EVP_MD_CTX* mdctx = nullptr;
      multicodec _code;
      std::size_t _size;
};

template< typename... Types >
inline multihash hash_n( multicodec code, Types&&... vars )
{
   multihash::digest_type result;
   encoder e( code );

//   variable_blob vb;
//   detail::pack_variadic_types( vb, std::forward< Types >( vars )... );

//   koinos::pack::to_binary( e, vb );
   e.get_result( result );
   return multihash( code, result );
}

template< typename T >
inline multihash hash( multicodec code, const T& t, std::size_t size = 0 )
{
   multihash::digest_type result;
   encoder e( code, size );
//   koinos::pack::to_binary( e, t );
   e.get_result( result );
   return multihash( code, result );
}

multihash hash_str( multicodec code, const char* data, size_t len, uint64_t size = 0 );


} // koinos::crypto
