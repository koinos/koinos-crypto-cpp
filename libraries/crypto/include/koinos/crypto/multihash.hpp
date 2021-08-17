#pragma once

#include <cstddef>
#include <sstream>

#include <openssl/evp.h>

#include <google/protobuf/message.h>

#include <koinos/exception.hpp>
#include <koinos/varint.hpp>

namespace koinos {

namespace crypto { class multihash; }

template< typename Stream >
inline void to_binary( Stream& s, const crypto::multihash& m );

template< typename Stream >
inline void from_binary( Stream& s, crypto::multihash& v );

namespace crypto {

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

   void write( const char* d, std::size_t len );
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

   multihash& operator =( const multihash& rhs );

   bool operator==( const multihash &rhs ) const;
   bool operator!=( const multihash &rhs ) const;
   bool operator< ( const multihash &rhs ) const;
   bool operator<=( const multihash &rhs ) const;
   bool operator> ( const multihash &rhs ) const;
   bool operator>=( const multihash &rhs ) const;

   template< class Container >
   Container as() const
   {
      std::stringstream stream;

      koinos::to_binary( stream, *this );
      std::string str = stream.str();

      Container b;
      b.resize( str.size() );
      std::transform( str.begin(), str.end(), b.begin(), []( char c ) { return reinterpret_cast< decltype( *b.begin() ) >( c ); } );

      static_assert( sizeof( *b.begin() ) == sizeof( std::byte ) );

      return b;
   }

   template< class Container >
   static multihash from( const Container& c )
   {
      multihash m;
      std::stringstream stream;

      for ( const auto& e : c )
         stream.write( reinterpret_cast< const char* >( &e ), sizeof( std::byte ) );

      koinos::from_binary( stream, m );

      static_assert( sizeof( *c.begin() ) == sizeof( std::byte ) );

      return m;
   }

private:
   multicodec  _code = multicodec::identity;
   digest_type _digest;
};

multihash hash( multicodec code, const std::vector< std::byte >& d, std::size_t size = 0 );
multihash hash( multicodec code, const std::string& s, std::size_t size = 0 );
multihash hash( multicodec code, const char* data, std::size_t len, std::size_t size = 0 );

template< typename T >
typename std::enable_if_t< std::is_member_function_pointer_v< decltype( &T::SerializeToString ) >, multihash >
hash( multicodec code, const T& t, std::size_t size = 0 )
{
   std::string s;

   t.SerializeToString( &s );

   return hash( code, s, size );
}

template< typename T >
typename std::enable_if_t< std::is_member_function_pointer_v< decltype( &T::SerializeToString ) >, multihash >
hash( multicodec code, T&& t, std::size_t size = 0 )
{
   return hash( code, t, size );
}

} // crypto

template< typename Stream >
inline void to_binary( Stream& s, const crypto::multihash& m )
{
   auto code = unsigned_varint( static_cast< std::underlying_type_t< crypto::multicodec > >( m.code() ) );
   auto size = unsigned_varint( m.digest().size() );

   to_binary( s, code );
   to_binary( s, size );
   s.write( reinterpret_cast< const char* >( m.digest().data() ), m.digest().size() );
}

template< typename Stream >
inline void from_binary( Stream& s, crypto::multihash& v )
{
   unsigned_varint     code;
   unsigned_varint     size;
   crypto::digest_type digest;

   from_binary( s, code );
   from_binary( s, size );

   digest.resize( size.value );
   s.read( reinterpret_cast< char* >( digest.data() ), size.value );

   v = crypto::multihash( static_cast< crypto::multicodec >( code.value ), digest );
}

} // koinos
