#pragma once

#include <iostream>
#include <memory>

#include <koinos/crypto/multihash.hpp>

namespace koinos::crypto {

template < class T >
class merkle_node
{
   std::unique_ptr< const merkle_node > _left, _right;
   multihash                            _hash;
   const std::shared_ptr< T >           _value;

public:
   merkle_node( multicodec code ) : _left( nullptr ), _right( nullptr ), _value( nullptr )
   {
      _hash = crypto::multihash::empty( code );
   }

   merkle_node( multicodec code, const T& value ) : _left( nullptr ), _right( nullptr ), _value( std::make_shared< T >( value ) )
   {
      _hash = crypto::hash_str( code, (char*)value.data(), value.size() );
   }

   merkle_node( multicodec code, std::unique_ptr< merkle_node< T > > left, std::unique_ptr< merkle_node< T > > right ) :
      _left( std::move( left ) ),
      _right( std::move( right ) ),
      _value( nullptr )
   {
      std::array< std::byte, 32 * 2 > double_digest;
      multihash left_digest;
      multihash right_digest;

      if ( _left == nullptr && _right == nullptr )
         throw std::runtime_error( "left and right nodes cannot be null in an intermediate node" );

      if ( _left != nullptr )
         left_digest = _left->hash();
      else
         left_digest = _right->hash();

      if ( _right != nullptr )
         right_digest = _right->hash();
      else
         right_digest = _left->hash();

      auto it = std::copy( std::begin( left_digest.digest() ), std::end( left_digest.digest() ), std::begin( double_digest ) );
      std::copy( std::begin( right_digest.digest() ), std::end( right_digest.digest() ), it );

      _hash = crypto::hash_str( code, (char*)double_digest.data(), double_digest.size() );
   }

   multihash hash() const { return _hash; }

   const merkle_node *left() const { return _left.get(); }
   const merkle_node *right() const { return _right.get(); }
};

template < class T >
class merkle_tree
{
   std::unique_ptr< merkle_node< T > > _root;

public:
   merkle_tree( multicodec code, std::vector< T > elements )
   {
      if ( !elements.size() )
      {
         _root = std::make_unique< merkle_node< T > >( code );
         return;
      }

      std::vector< std::unique_ptr< merkle_node< T > > > processed_nodes;

      for ( auto& e : elements )
         processed_nodes.push_back( std::make_unique< merkle_node< T > >( code, e ) );

      auto created_nodes = processed_nodes.size();
      while ( created_nodes > 1 )
      {
         std::vector< std::unique_ptr< merkle_node< T > > > new_nodes;
         for ( size_t index = 0; index < processed_nodes.size(); )
         {
            std::unique_ptr< merkle_node< T > > left  = nullptr;
            std::unique_ptr< merkle_node< T > > right = nullptr;

            if ( index < processed_nodes.size() )
               left = std::move( processed_nodes[ index++ ] );

            if ( index < processed_nodes.size() )
            {
               right = std::move( processed_nodes[ index++ ] );
               new_nodes.push_back( std::make_unique< merkle_node< T > >( code, std::move( left ), std::move( right ) ) );
            }
            else
            {
               new_nodes.push_back( std::move( left ) );
            }
         }
         created_nodes = new_nodes.size();
         processed_nodes = std::move( new_nodes );
      }

      _root = std::move( processed_nodes.front() );
   }

   const std::unique_ptr< merkle_node< T > >& root()
   {
      return _root;
   }
};

} // koinos::crypto
