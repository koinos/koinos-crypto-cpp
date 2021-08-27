#pragma once

#include <cstddef>
#include <ostream>
#include <sstream>

#include <openssl/evp.h>

#include <google/protobuf/message.h>

#include <koinos/exception.hpp>
#include <koinos/type_traits.hpp>
#include <koinos/varint.hpp>

namespace google::protobuf{ class Message; }

namespace koinos {

namespace crypto { class multihash; }

template<>
void to_binary< crypto::multihash >( std::ostream& s, const crypto::multihash& m );

template<>
void from_binary< crypto::multihash >( std::istream& s, crypto::multihash& v );

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

class multihash
{
public:
   multihash() = default;
   multihash( multicodec code, const digest_type& digest );
   multihash( multicodec code, digest_type&& digest );

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

   friend std::ostream& operator<<( std::ostream&, const multihash& );

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

namespace detail {

struct encoder final : std::streambuf, std::ostream
{
   encoder( multicodec code, std::size_t size = 0 );
   encoder( const encoder& ) = delete;
   encoder( encoder&& ) = delete;
   ~encoder();

   std::streamsize xsputn( const char* s, std::streamsize n ) override;

   void write( const char* d, std::size_t len );
   void put( char c );
   void reset();
   void set_size( std::size_t size = 0 );
   multihash get_hash();

   private:
      const EVP_MD* md = nullptr;
      EVP_MD_CTX* mdctx = nullptr;
      multicodec _code;
      std::size_t _size;
};

void hash_impl( encoder& e, const std::vector< std::byte >& d );
void hash_impl( encoder& e, const std::string& s );
void hash_impl( encoder& e, const char* data, std::size_t len );
void hash_impl( encoder& e, const multihash& m );

template< class T >
std::enable_if_t< std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, const T& t )
{
   t.SerializeToOstream( &e );
}

template< class T >
std::enable_if_t< has_to_binary_v< T > && !std::is_same_v< T, multihash >, void >
hash_impl( encoder& e, const T& t )
{
   to_binary( e, t );
}

inline void hash_n_impl( encoder& e ) {} // Base cases for recursive templating

inline void hash_n_impl( encoder& e, std::size_t size )
{
   e.set_size( size );
}

template< class... Ts >
void hash_n_impl( encoder& e, const char* data, std::size_t len, Ts... ts )
{
   hash_impl( e, data, len );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, char* data, std::size_t len, Ts... ts )
{
   hash_impl( e, data, len );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class T, class... Ts >
void hash_n_impl( encoder& e, T&& t, Ts... ts )
{
   hash_impl( e, t );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

} // detail

template< class... Ts >
multihash hash( multicodec code, Ts... ts )
{
   detail::encoder e( code );
   detail::hash_n_impl( e, std::forward< Ts >( ts )... );
   return e.get_hash();
}

std::ostream& operator<<( std::ostream&, const crypto::multihash& );

} // crypto

} // koinos
