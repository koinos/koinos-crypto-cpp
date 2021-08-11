#pragma once

#include <cstddef>

#include <openssl/evp.h>

#include <capnp/message.h>

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

using digest_type = std::vector< std::byte >;

struct encoder
{
   encoder( multicodec code, std::size_t size = 0 );
   ~encoder();

   void write( const char* d, size_t len );
   void put( char c ) { write( &c, 1 ); }
   void reset();
   void get_result( digest_type& v );

   private:
      const EVP_MD* md = nullptr;
      EVP_MD_CTX* mdctx = nullptr;
      multicodec _code;
      std::size_t _size;
};

class multihash
{
public:
   multihash() = default;
   multihash( multicodec code, digest_type digest );

   multicodec           code() const;
   const digest_type&   digest() const;
   bool                 is_zero() const;

   static std::size_t   standard_size( multicodec id );
   static multihash     zero( multicodec id, std::size_t size = 0 );
   static multihash     empty( multicodec id, std::size_t size = 0 );

   bool operator==( const multihash &rhs ) const;
   bool operator!=( const multihash &rhs ) const;

private:
   multicodec  _code = multicodec::identity;
   digest_type _digest;
};

multihash hash( multicodec code, const std::vector< std::byte >& d, std::size_t size = 0 );
multihash hash( multicodec code, const std::string& s, std::size_t size = 0 );
multihash hash( multicodec code, const char* data, std::size_t len, std::size_t size = 0 );

template< typename T >
typename std::enable_if< std::is_class< typename T::Builds >::value, multihash >::type
hash( multicodec code, const T& t, std::size_t size = 0 )
{
   auto canonical_words = capnp::canonicalize( t.asReader() );
   auto capnp_bytes = canonical_words.asBytes();

   std::vector< std::byte > bytes(
      reinterpret_cast< std::byte* >( capnp_bytes.begin() ),
      reinterpret_cast< std::byte* >( capnp_bytes.end() )
   );

   return hash( code, bytes, size );
}

template< typename T >
typename std::enable_if< std::is_class< typename T::Builds >::value, multihash >::type
hash( multicodec code, T&& t, std::size_t size = 0 )
{
   return hash( code, std::forward< T >( t ), size );
}

} // koinos::crypto
