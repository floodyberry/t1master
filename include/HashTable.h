#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

/*
	Supports common types
*/

#include <string.h>

unsigned int hashseed = 0x811C9DC5;
inline void sethashseed( unsigned int s ) { hashseed = s; }

inline unsigned int hashint( unsigned int a ) {
	a ^=  (hashseed);
	a += ~(a<<15);
	a ^=  (a>>10);
	a +=  (a<<3);
	a ^=  (a>>6);
	a += ~(a<<11);
	a ^=  (a>>16);
	return ( a );
}

inline unsigned int fnv( const char *a ) {
	unsigned int hash = ( hashseed );
	while ( *a ) 
		hash = ( hash ^ (unsigned char )*a++ ) * 16777619;
	return ( hash );
}

struct KeyTool {
	unsigned int hash( unsigned int a ) const { return hashint( a ); }
	bool compare( unsigned int a, unsigned int b ) const { return ( a == b ); } 

	unsigned int hash( const char *a ) const { return ( fnv( a ) ); }
	bool compare( const char *a, const char *b ) const { return ( strcmp( a, b ) == 0 ); } 
};

/*
	HashTable<
		key_type,
		value_type,
		keytool => KeyTool( implements .hash(key) & .compare(key,key) )
	>
*/

template < class key_type, class value_type, class keytool = KeyTool >
struct HashTable {
	typedef key_type Key;
	typedef value_type Value;

	/*
		Node
	*/

	struct Node {
		Node( const key_type &key, const value_type &value, Node *next ) : mNext(next) {  mValue = ( value ); mKey = ( key );  }
		~Node( ) { /* deleter()( mKey, mValue ); */ }

		Node *mNext;
		key_type mKey;
		value_type mValue;		
	};

	/*
		Iterator
	*/
	friend struct Iterator;

	struct Iterator {
		friend struct HashTable;
		Iterator( ) : mNode(NULL) {}
		Iterator( HashTable *hash ) : mNode(NULL), mHash(hash), mBucketOn(-1)  { NextActiveBucket(); }

		key_type &key() const { return ( mNode->mKey );	}
		value_type &value() const { return ( mNode->mValue ); }
		void Delete() { mHash->Delete( *this ); }

		Iterator &operator++ ( ) {
			if ( mNode ) {
				mNode = ( mNode->mNext );
				NextActiveBucket( );
			}

			return ( *this );
		}

		bool operator!= ( Iterator &b ) { return ( mNode != b.mNode ); }
		bool operator== ( Iterator &b ) { return ( mNode == b.mNode ); }

	protected:
		void NextActiveBucket( ) {
			while ( !mNode && ( mBucketOn < ( mHash->mBucketCount - 1 ) ) )
				mNode = ( mHash->mBuckets[ ++mBucketOn ] );
		}

		Node *mNode;
		HashTable *mHash;		
		int mBucketOn;
	};

	
	/*
		Hash Table
	*/

	HashTable( int num_buckets = 4 ) : mItemCount(0) {
		mBucketCount = ( SmallestPow2( num_buckets ) );
		mBucketMask = ( mBucketCount - 1 );

		mBuckets = new Node*[ mBucketCount ];
		memset( mBuckets, 0, sizeof( Node* ) * mBucketCount );
	}

	~HashTable( ) {
		Clear( );
		delete[] mBuckets;
		mBuckets = ( NULL );
	}

	Iterator Begin( ) {
		if ( !mItemCount )
			return ( End( ) );
		
		return ( Iterator( this ) );
	}

	size_t Bucket( const key_type &key, int mask ) const {
		return ( mKeytool.hash( key ) & mask );
	}

	size_t Bucket( const key_type &key ) const {
		return ( Bucket( key, mBucketMask ) );
	}

	void Clear( ) {
		if ( !mItemCount )
			return;

		for ( int i = 0; i < mBucketCount; i++ ) {
			Node *node = ( mBuckets[ i ] );
			while ( node ) {
				Node *next = ( node->mNext );
				delete node;
				node = next;
			}
			
			mBuckets[ i ] = NULL;
		}

		mItemCount = 0;
	}

	void Compact( ) {	
		Resize( SmallestPow2( mItemCount ) );
	}

	int Count( ) const {
		return ( mItemCount );
	}

	void Delete( const key_type &key ) {
		Node **head = ( &mBuckets[ Bucket( key ) ] );
		Node *node = ( *head ), *prev = ( NULL );

		for ( ; node; node = ( node->mNext ) ) {
			if ( mKeytool.compare( node->mKey, key ) ) {
				Unlink( head, prev, node );
				break;
			} else {
				prev = ( node );				
			}
		}
	}

	// delete advances the iterator
	void Delete( Iterator &iter ) {
		if ( !iter.mNode || ( iter.mBucketOn >= mBucketCount ) )
			return;

		Node **head = ( &mBuckets[ iter.mBucketOn ] ), *node = ( *head ), *prev = ( NULL );
		for ( ; node && ( node != iter.mNode ); prev = node, node = node->mNext ) {}

		if ( node != iter.mNode )
			return;

		iter.mNode = Unlink( head, prev, node );
		if ( !iter.mNode ) 
			iter.NextActiveBucket();
	}

	Iterator End( ) {
		Iterator end = Iterator( );
		return ( end );
	}

	value_type *Find( const key_type &key ) const {
		Node **head = ( &mBuckets[ Bucket( key ) ] );

		for ( Node *node = *head; node; node = node->mNext ) {
			if ( mKeytool.compare( node->mKey, key ) )
				return ( &node->mValue );
		}

		return ( NULL );
	}

	template< class MapTo >
	void Filter( MapTo &filter ) {
		Node **head = ( mBuckets ), **end = ( mBuckets + mBucketCount );
		for ( ; head < end; ++head ) {
			Node *node = ( *head ), *prev = ( NULL );
			while ( node ) {
				if ( !filter( node->mKey, node->mValue ) ) {
					node = Unlink( head, prev, node );
				} else {
					prev = ( node );
					node = ( node->mNext );
				}
			}
		}

		Compact();
	}

	value_type &Insert( const key_type &key, const value_type &value ) {
		CheckIncrease();
		Node **head = ( &mBuckets[ Bucket( key ) ] );
		return ( Link( head, key, value ) );
	}

	value_type &InsertUnique( const key_type &key, const value_type &value ) {
		CheckIncrease();

		Node **head = ( &mBuckets[ Bucket( key ) ] );
		for ( Node *node = *head; node; node = node->mNext ) {
			if ( mKeytool.compare( node->mKey, key ) )
				return ( node->mValue );
		}
		
		return ( Link( head, key, value ) );
	}

	int Size( ) {
		return ( mItemCount );
	}

	int SmallestPow2( int cap ) const {
		int count = ( 4 );
		while ( count < cap )
			count <<= 1;
		return ( count );
	}

	value_type &operator[] ( const key_type &key ) {
		return ( InsertUnique( key, value_type() ) );
	}

private:
	value_type &Link( Node **bucket, const key_type &key, const value_type &value ) {
		*bucket = new Node( key, value, *bucket );
		mItemCount++;
		return ( (*bucket)->mValue );
	}

	Node *Unlink( Node **bucket, Node *prev, Node *node ) {
		Node *next = ( node->mNext );
		if ( prev )
			prev->mNext = ( next );
		else
			*bucket = ( next );

		delete node;
		--mItemCount;
		return ( next );
	}


	void CheckIncrease( ) {
		if ( mBucketCount <= mItemCount )
			Resize( mBucketCount << 1 );
	}

	void Resize( int bucket_count ) {
		if ( mBucketCount == bucket_count )
			return;

		Node **new_buckets = new Node*[ bucket_count ];
		memset( new_buckets, 0, sizeof( Node** ) * bucket_count );

		for ( int i = 0; i < mBucketCount; i++ ) {
			Node *node = ( mBuckets[ i ] );
			while ( node ) {
				Node *next = ( node->mNext );
				Node **head = &new_buckets[ Bucket( node->mKey, ( bucket_count - 1 ) ) ];
				node->mNext = ( *head );
				*head = node;
				node = ( next );
			}
		}

		delete[] mBuckets;
		mBuckets = ( new_buckets );
		mBucketCount = ( bucket_count );
		mBucketMask = ( bucket_count - 1 );
	}


	Node **mBuckets;
	int mBucketCount, mBucketMask, mItemCount;
	keytool mKeytool;
};


#endif // __HASHTABLE_H__
