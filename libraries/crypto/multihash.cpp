#include <koinos/crypto/multihash.hpp>

#define HASH_OFFSET (8)
#define HASH_MASK (~uint64_t(0)<<8)
#define SIZE_MASK ~HASH_MASK

#include <iostream>
#include <map>

namespace koinos::crypto {

multihash::multihash( multicodec code, digest_type digest ) : _code( code ), _digest( digest ) {}

multicodec multihash::code() const
{
   return _code;
}

const multihash::digest_type& multihash::digest() const
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
   multihash::digest_type result;

   if ( !size )
      size = multihash::standard_size( code );

   result.resize( size );
   std::memset( result.data(), 0, size );
   return multihash( code, result );
}

multihash multihash::empty( multicodec code, std::size_t size )
{
   char c;
   return hash_str( code, &c, 0, size );
}

bool multihash::is_zero() const
{
   return std::all_of( _digest.begin(), _digest.end(), []( std::byte b ) { return b == std::byte{ 0x00 }; } );
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

encoder::encoder( multicodec code, std::size_t size )
{
   static const uint64_t MAX_HASH_SIZE = std::min< uint64_t >(
      {std::numeric_limits< uint8_t >::max(),              // We potentially store the size in uint8_t value
       std::numeric_limits< unsigned int >::max(),         // We cast the size to unsigned int for openssl call
       EVP_MAX_MD_SIZE                                     // Max size supported by OpenSSL library
      });

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

void encoder::write( const char* d, size_t len )
{
   EVP_DigestUpdate( mdctx, d, len );
};

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

void encoder::get_result( std::vector< std::byte >& v )
{
   unsigned int size = (unsigned int) _size;
   v.resize( _size );

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
}


multihash hash_str( multicodec code, const char* data, size_t len, uint64_t size )
{
   multihash::digest_type result;
   encoder e( code, size );
   e.write( data, len );
   e.get_result( result );
   return multihash( code, result );
}

} // koinos::crypto
