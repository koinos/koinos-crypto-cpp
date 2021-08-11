#pragma once

#include <iostream>
#include <memory>

#include <koinos/crypto/multihash.hpp>

namespace koinos::crypto {

template < class T >
class merkle_node
{
public:
   merkle_node( multicodec code ) : _left( nullptr ), _right( nullptr ), _value( nullptr )
   {
      _hash = crypto::multihash::empty( code );
   }

   merkle_node( multicodec code, const T& value ) : _left( nullptr ), _right( nullptr ), _value( std::make_shared< T >( value ) )
   {
      _hash = crypto::hash( code, (char*)value.data(), value.size() );
   }

   merkle_node( multicodec code, std::unique_ptr< merkle_node< T > > l, std::unique_ptr< merkle_node< T > > r ) :
      _left( std::move( l ) ),
      _right( std::move( r ) ),
      _value( nullptr )
   {
      std::vector< std::byte > buffer;
      std::copy( left()->hash().digest().begin(), left()->hash().digest().end(), std::back_inserter( buffer ) );
      std::copy( right()->hash().digest().begin(), right()->hash().digest().end(), std::back_inserter( buffer ) );

      _hash = crypto::hash( code, (char*)buffer.data(), buffer.size() );
   }

   const multihash&                           hash() const { return _hash; }
   const std::unique_ptr< merkle_node< T > >& left() const { return _left; }
   const std::unique_ptr< merkle_node< T > >& right() const { return _right; }
   const std::shared_ptr< T >&                value() const { return _value; }

private:
   std::unique_ptr< merkle_node< T > >  _left, _right;
   multihash                            _hash;
   const std::shared_ptr< T >           _value;
};

template < class T >
class merkle_tree
{
public:
   using node_type = merkle_node< T >;

   merkle_tree( multicodec code, const std::vector< T >& elements )
   {
      if ( !elements.size() )
      {
         _root = std::make_unique< node_type >( code );
         return;
      }

      std::vector< std::unique_ptr< node_type > > nodes;

      for ( auto& e : elements )
         nodes.push_back( std::make_unique< node_type >( code, e ) );

      auto count = nodes.size();

      while ( count > 1 )
      {
         std::vector< std::unique_ptr< node_type > > new_nodes;

         for ( std::size_t index = 0; index < nodes.size(); index++ )
         {
            auto left = std::move( nodes[ index ] );

            if ( index + 1 < nodes.size() )
            {
               auto right = std::move( nodes[ ++index ] );
               new_nodes.push_back( std::make_unique< node_type >( code, std::move( left ), std::move( right ) ) );
            }
            else
            {
               new_nodes.push_back( std::move( left ) );
            }
         }

         count = new_nodes.size();
         nodes = std::move( new_nodes );
      }

      _root = std::move( nodes.front() );
   }

   const std::unique_ptr< node_type >& root()
   {
      return _root;
   }

private:
   std::unique_ptr< node_type > _root;
};

} // koinos::crypto
