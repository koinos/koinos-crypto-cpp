#include <koinos/crypto/multihash.hpp>

#define HASH_OFFSET (8)
#define HASH_MASK (~uint64_t(0)<<8)
#define SIZE_MASK ~HASH_MASK

#include <iostream>
#include <map>

#include <google/protobuf/stubs/strutil.h>

namespace koinos { namespace crypto {

multihash::multihash( multicodec code, const digest_type& digest ) : _code( code ), _digest( digest ) {}
multihash::multihash( multicodec code, digest_type&& digest )      : _code( code ), _digest( digest ) {}

multicodec multihash::code() const
{
   return _code;
}

const digest_type& multihash::digest() const
{
   return _digest;
}

std::size_t multihash::standard_size( multicodec id )
{
   switch( id )
   {
      case multicodec::sha1:
         return 20;
      case multicodec::sha2_256:
         return 32;
      case multicodec::sha2_512:
         return 64;
      case multicodec::ripemd_160:
         return 20;
      default:
         KOINOS_ASSERT( false, unknown_hash_algorithm, "unknown hash code ${i}", ("i", static_cast< std::underlying_type_t< multicodec > >( id )) );
   }
}

multihash multihash::zero( multicodec code, std::size_t size )
{
   digest_type result;

   if ( !size )
      size = multihash::standard_size( code );

   result.resize( size );
   std::memset( result.data(), 0, size );
   return multihash( code, result );
}

multihash multihash::empty( multicodec code, std::size_t size )
{
   char c;
   return hash( code, &c, 0, size );
}

bool multihash::is_zero() const
{
   return std::all_of( _digest.begin(), _digest.end(), []( std::byte b ) { return b == std::byte{ 0x00 }; } );
}

multihash& multihash::operator=( const multihash& rhs )
{
   _code = rhs._code;

   _digest.resize( rhs._digest.size() );
   std::copy( rhs._digest.begin(), rhs._digest.end(), _digest.begin() );

   return *this;
}

bool multihash::operator==( const multihash& rhs ) const
{
   return _code == rhs._code && _digest == rhs._digest;
}

bool multihash::operator!=( const multihash& rhs ) const
{
   return !( *this == rhs );
}

bool multihash::operator<( const multihash &rhs ) const
{
   return _code < rhs._code || _digest < rhs._digest;
}

bool multihash::operator>( const multihash &rhs ) const
{
   return _code > rhs._code || _digest > rhs._digest;
}

bool multihash::operator<=( const multihash &rhs ) const
{
   return *this < rhs || *this == rhs;
}

bool multihash::operator>=( const multihash &rhs ) const
{
   return *this > rhs || *this == rhs;
}

const EVP_MD* get_evp_md( multicodec code )
{
   static const std::map< multicodec, const EVP_MD* > evp_md_map = {
      { multicodec::sha1      , EVP_sha1()      },
      { multicodec::sha2_256  , EVP_sha256()    },
      { multicodec::sha2_512  , EVP_sha512()    },
      { multicodec::ripemd_160, EVP_ripemd160() }
   };

   auto md_itr = evp_md_map.find( code );
   return md_itr != evp_md_map.end() ? md_itr->second : nullptr;
}

namespace detail {

encoder::encoder( multicodec code, std::size_t size ) :
   std::streambuf(), std::ostream( this )
{
   static const uint64_t MAX_HASH_SIZE = std::min< uint64_t >(
   {
      std::numeric_limits< uint8_t >::max(),      // We potentially store the size in uint8_t value
      std::numeric_limits< unsigned int >::max(), // We cast the size to unsigned int for openssl call
      EVP_MAX_MD_SIZE                             // Max size supported by OpenSSL library
   } );

   _code = code;

   if ( size == 0 )
      size = multihash::standard_size( code );

   KOINOS_ASSERT(
      size <= MAX_HASH_SIZE,
      multihash_size_limit_exceeded,
      "requested hash size ${size} is larger than max size ${max}", ("size", size)("max", MAX_HASH_SIZE)
   );

   _size = size;
   OpenSSL_add_all_digests();
   md = get_evp_md( code );
   KOINOS_ASSERT( md, unknown_hash_algorithm, "unknown hash id ${i}", ("i", static_cast< std::underlying_type_t< multicodec > >( code )) );
   mdctx = EVP_MD_CTX_create();
   EVP_DigestInit_ex( mdctx, md, NULL );
}

encoder::~encoder()
{
   if ( mdctx )
      EVP_MD_CTX_destroy( mdctx );
}

std::streamsize encoder::xsputn( const char* d, std::streamsize n )
{
   EVP_DigestUpdate( mdctx, d, n );
   pbump( n );
   return n;
}

void encoder::write( const char* d, size_t len )
{
   xsputn( d, len );
}

void encoder::put( char c )
{
   xsputn( &c, 1 );
}

void encoder::reset()
{
   if( mdctx )
      EVP_MD_CTX_destroy( mdctx );

   if ( md )
   {
      mdctx = EVP_MD_CTX_create();
      EVP_DigestInit_ex( mdctx, md, NULL );
   }
}

multihash encoder::get_hash()
{
   unsigned int size = (unsigned int) _size;
   std::vector< std::byte > v( size );

   KOINOS_ASSERT(
      EVP_DigestFinal_ex( mdctx, (unsigned char*)( v.data() ), &size ),
      koinos::exception, "EVP_DigestFinal_ex returned failure"
   );

   KOINOS_ASSERT(
      size == _size,
      multihash_size_mismatch,
      "OpenSSL EVP_DigestFinal_ex returned hash size ${size}, does not match expected hash size ${_size}",
      ("size", size)("_size", _size)
   );

   return multihash( _code, std::move( v ) );
}

void hash_impl( encoder& e, const std::vector< std::byte >& d )
{
   hash_impl( e, reinterpret_cast< const char * >( d.data() ), d.size() );
}

void hash_impl( encoder& e, const std::string& s )
{
   hash_impl( e, s.data(), s.size() );
}

void hash_impl( encoder& e, const char* data, std::size_t len )
{
   e.write( data, len );
}

} // detail

multihash hash( multicodec code, const std::vector< std::byte >& d, std::size_t size )
{
   return hash( code, reinterpret_cast< const char* >( d.data() ), d.size(), size );
}

multihash hash( multicodec code, const std::string& s, std::size_t size )
{
   return hash( code, s.data(), s.size(), size );
}

multihash hash( multicodec code, const char* data, std::size_t len, std::size_t size )
{
   detail::encoder e( code, size );
   detail::hash_impl( e, data, len );
   return e.get_hash();
}

std::ostream& operator<<( std::ostream& out, const crypto::multihash& mh )
{
   std::stringstream bin;
   to_binary( bin, mh );
   std::string base64;
   google::protobuf::WebSafeBase64EscapeWithPadding( bin.str(), &base64 );
   return out << base64;
}

} // crypto

template<>
void to_binary< crypto::multihash >( std::ostream& s, const crypto::multihash& m )
{
   auto code = unsigned_varint( static_cast< std::underlying_type_t< crypto::multicodec > >( m.code() ) );
   auto size = unsigned_varint( m.digest().size() );

   to_binary( s, code );
   to_binary( s, size );
   s.write( reinterpret_cast< const char* >( m.digest().data() ), m.digest().size() );
}

template<>
void from_binary< crypto::multihash >( std::istream& s, crypto::multihash& v )
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
