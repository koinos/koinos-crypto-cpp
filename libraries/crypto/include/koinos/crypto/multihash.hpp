#pragma once

#include <cstddef>
#include <ostream>
#include <sstream>

#include <openssl/evp.h>

#include <google/protobuf/message.h>

#include <koinos/exception.hpp>
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

enum class digest_size : std::size_t {};

class multihash
{
public:
   multihash() = default;
   multihash( multicodec code, const digest_type& digest );
   multihash( multicodec code, digest_type&& digest );

   multicodec           code() const;
   const digest_type&   digest() const;
   bool                 is_zero() const;

   static digest_size   standard_size( multicodec id );
   static multihash     zero( multicodec id, digest_size size = digest_size( 0 ) );
   static multihash     empty( multicodec id, digest_size size = digest_size( 0 ) );

   multihash& operator =( const multihash& rhs );

   bool operator==( const multihash &rhs ) const;
   bool operator!=( const multihash &rhs ) const;
   bool operator< ( const multihash &rhs ) const;
   bool operator<=( const multihash &rhs ) const;
   bool operator> ( const multihash &rhs ) const;
   bool operator>=( const multihash &rhs ) const;

   friend std::ostream& operator<<( std::ostream&, const multihash& );

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

void hash_c_str( encoder& e, const char* data, std::size_t len );
void hash_bytes( encoder& e, const std::vector< std::byte >& d );
void hash_str( encoder& e, const std::string& s );
void hash_multihash( encoder& e, const multihash& m );

template< class T >
std::enable_if_t< std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, const T& t )
{
   t.SerializeToOstream( &e );
}

template< class T >
std::enable_if_t< std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, const T* t )
{
   t->SerializeToOstream( &e );
}

template< class T >
std::enable_if_t< std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, T* t )
{
   t->SerializeToOstream( &e );
}

template< class T >
std::enable_if_t< !std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, const T& t )
{
   to_binary( e, t );
}

template< class T >
std::enable_if_t< !std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, const T* t )
{
   to_binary( e, *t );
}

template< class T >
std::enable_if_t< !std::is_base_of_v< google::protobuf::Message, T >, void >
hash_impl( encoder& e, T* t )
{
   to_binary( e, *t );
}

inline void hash_n_impl( encoder& e ) {} // Base cases for recursive templating

inline void hash_n_impl( encoder& e, digest_size size )
{
   e.set_size( std::size_t( size ) );
}

template< class... Ts >
void hash_n_impl( encoder& e, const char* data, std::size_t len, Ts... ts )
{
   hash_c_str( e, data, len );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, char* data, std::size_t len, Ts... ts )
{
   hash_c_str( e, data, len );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, const multihash& m, Ts... ts )
{
   hash_multihash( e, m );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, multihash&& m, Ts... ts )
{
   hash_multihash( e, m );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, const std::vector< std::byte >& d, Ts... ts )
{
   hash_bytes( e, d );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, std::vector< std::byte >&& d, Ts... ts )
{
   hash_bytes( e, d );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, const std::string& s, Ts... ts )
{
   hash_str( e, s );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class... Ts >
void hash_n_impl( encoder& e, std::string&& s, Ts... ts )
{
   hash_str( e, s );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

template< class T, class... Ts >
void hash_n_impl( encoder& e, T&& t, Ts... ts )
{
   hash_impl( e, t );
   hash_n_impl( e, std::forward< Ts >( ts )... );
}

} // detail

/*
 * hash() hashes a series of objects in to a single hash.
 *
 * Types currently supported:
 *
 * - std::string
 * - std::vector< std::byte >
 * - C string (const char*, size_t)
 * - Protobuf generated types (google::protobuf::Message)
 * - Types implementing `to_binary( std::ostream&, const T& )`
 *
 * If the last parameter is digest_size, a custom hash size will be used.
 * Effectively, the function's signature is hash( multicodec code, Ts... ts, size_t size = 0 )
 */
template< class... Ts >
multihash hash( multicodec code, Ts... ts )
{
   detail::encoder e( code );
   detail::hash_n_impl( e, std::forward< Ts >( ts )... );
   return e.get_hash();
}

std::ostream& operator<<( std::ostream&, const crypto::multihash& );

void to_json( nlohmann::json&, const multihash& );

} // crypto

} // koinos
