#pragma once

#include <koinos/binary.hpp>
#include <koinos/crypto/multihash.hpp>
#include <koinos/exception.hpp>

namespace koinos { namespace crypto {

   using recoverable_signature = std::array< std::byte, 65 >; ///< A 65 byte recoverable ECDSA siganture
   using compressed_public_key = std::array< std::byte, 33 >; ///< The 33 byte compressed ECDSA public key
   using private_key_secret    = std::array< std::byte, 32 >; ///< The 32 byte ECDSA prvate key secret

   KOINOS_DECLARE_EXCEPTION( key_serialization_error );
   KOINOS_DECLARE_EXCEPTION( key_recovery_error );
   KOINOS_DECLARE_EXCEPTION( key_manipulation_error );
   KOINOS_DECLARE_EXCEPTION( signing_error );

   namespace detail { struct public_key_impl; }

   /**
    *  @class public_key
    *  @brief contains only the public point of an elliptic curve key.
    *
    *  This is a wrapper around a 64 byte ECDSA public key and to interface with secp256k functions.
    *  Internally, they key is 64 bytes, but when serialized it is a 33 byte compressed public key.
    */
   class public_key
   {
      public:
         public_key();
         public_key( const public_key& k );
         public_key( public_key&& pk );

         ~public_key();

         compressed_public_key serialize() const;
         static public_key deserialize( const compressed_public_key& cpk );

         operator compressed_public_key() const { return serialize(); }

         /**
          * Recovers a public key from a 65 byte recoverable signature (R, S, rec_id).
          * The signature must be in the "canonical" format where S < N/2 mod N.
          * Signatures generated by this library are guaranteed to be canonical, but
          * canonicity needs to be checked nonetheless.
          *
          * @param sig A 65 byte recoverable signature
          * @param digest The sha256 digest that was signed
          *
          * @throw koinos_exception a public key could not be recovered from the signature
          */
         static public_key recover( const recoverable_signature& sig, const multihash& digest );

         /** Computes new pubkey = regenerate(offset).pubkey + old pubkey
         *                      = offset * G + 1 * old pubkey ?! */
         public_key add( const multihash& offset ) const;

         bool valid() const;

         multihash verify_random_proof( const std::string& input, const std::string& proof ) const;

         public_key& operator =( public_key&& pk );
         public_key& operator =( const public_key& pk );

         friend bool operator ==( const public_key& a, const public_key& b );

         friend bool operator !=( const public_key& a, const public_key& b )
         {
            return !(a == b);
         }

         std::string to_address_bytes( std::byte prefix = std::byte{ 0x00 } ) const;

         unsigned int fingerprint() const;

         static bool is_canonical( const recoverable_signature& c );

      private:
         friend class private_key;

         std::unique_ptr< detail::public_key_impl > _my;
   };

   /**
    *  @class private_key
    *  @brief an elliptic curve private key.
    *
    *  This is a wrapper around a 64 byte ECDSA
    */
   class private_key
   {
      public:
         private_key();
         private_key( private_key&& pk );
         private_key( const private_key& pk );
         ~private_key();

         private_key& operator=( private_key&& pk );
         private_key& operator=( const private_key& pk );

         static private_key regenerate( const multihash& secret );

         /**
         *  This method of generation enables creating a new private key in a deterministic manner relative to
         *  an initial seed.   A public_key created from the seed can be multiplied by the offset to calculate
         *  the new public key without having to know the private key.
         */
         static private_key generate_from_seed( const multihash& seed, const multihash& offset = multihash() );

         private_key_secret get_secret() const; // get the private key secret

         operator private_key_secret () const { return get_secret(); }

         recoverable_signature sign_compact( const multihash& digest ) const;

         std::pair< std::string, multihash > generate_random_proof( const std::string& input ) const;

         public_key get_public_key() const;

         inline friend bool operator==( const private_key& a, const private_key& b )
         {
            return std::memcmp( a.get_secret().data(), b.get_secret().data(), 32 ) == 0;
         }

         inline friend bool operator!=( const private_key& a, const private_key& b )
         {
            return !(a == b);
         }

         inline friend bool operator<( const private_key& a, const private_key& b )
         {
            return std::memcmp( a.get_secret().data(), b.get_secret().data(), 32 ) < 0;
         }

         unsigned int fingerprint() const { return get_public_key().fingerprint(); }

         std::string to_wif( std::byte prefix = std::byte{ 0x80 } );
         static private_key from_wif( const std::string& b58, std::byte prefix = std::byte{ 0x80 } );

      private:
         private_key_secret _key;
   };

} // crypto

template<>
void to_binary< crypto::public_key >( std::ostream& s, const crypto::public_key& k );

template<>
void from_binary< crypto::public_key >( std::istream& s, crypto::public_key& k );

} // koinos
