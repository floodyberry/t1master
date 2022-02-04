// http://floodyberry.wordpress.com/2008/02/15/writing-a-tribes-1-master-server/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
	#define WIN32_LEAN_AND_MEAN
	#include <winsock2.h>
	#include <conio.h>
	typedef signed char int8_t;
	typedef unsigned char uint8_t;
	typedef unsigned short uint16_t;
	typedef signed int int32_t;
	typedef unsigned int uint32_t;
	typedef int socklen_t;
	#define EAGAIN WSAEWOULDBLOCK
#else
	#include <unistd.h>
	#include <sys/time.h>
	#include <sys/ioctl.h>
	#include <sys/select.h>
	#include <sys/socket.h>
	#include <sys/times.h>
	#include <sys/types.h>
	#include <arpa/inet.h>
	#include <sys/param.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <errno.h>
	#include <signal.h>
	#include <stdint.h>

	#define closesocket close
	#define ioctlsocket ioctl
#endif

#include "HashTable.h"

typedef   int8_t  s8;
typedef  uint8_t  u8;
typedef uint16_t u16;
typedef  int32_t s32;
typedef uint32_t u32;

const char *MASTER_FROM                 = ( "Tribes Master" );
const char *MASTER_MOTD                 = ( "Andrew's Master Server" );
const u32 UDP_HEADER_SIZE               = (     28 );
const u32 MASTER_PACKET_SIZE            = (    500 ) - UDP_HEADER_SIZE;
const u32 MASTER_UPLOAD_RATE            = (   5120 ); // 5kb/s limit per client
const u32 MASTER_SERVER_CHECK_INTERVAL  = (  60000 ); // Timeout servers every minute
const u32 MASTER_SERVER_TIMEOUT         = ( 250000 ); // 4m 10s timeout
      u32 MASTER_SERVER_MAXIPS          = (      5 );
const u32 MASTER_PENDING_CHECK_INTERVAL = (  10000 ); // Clean up pending every 10 seconds
const u32 MASTER_PENDING_TIMEOUT        = (   5000 ); // 5 second timeout
const u32 MASTER_PENALTY_CHECK_INTERVAL = (   5000 ); // Decrease penalties every 5 seconds
const s32 MASTER_SPAM_BANPENALTY        = (     50 ); // Penalty amount that results in a ban
const s32 MASTER_SPAM_LISTPENALTY       = (      5 ); // +Penalty per server list request
const s32 MASTER_SPAM_HEARTBEATPENALTY  = (      5 ); // +Penalty per heartbeat
const s32 MASTER_SPAM_PENALTYCAP        = ( MASTER_SPAM_BANPENALTY + 10 ); // Penalty maxes out at 10 seconds
const u32 MASTER_INTERVAL_WAKE          = ( 1000 * MASTER_PACKET_SIZE / MASTER_UPLOAD_RATE ); // Wake up to send a batch of Packets


template< class type > type Min( const type &a, const type &b ) { return ( a < b ) ? a : b; }
template< class type > type Max( const type &a, const type &b ) { return ( a > b ) ? a : b; }

inline u32 currentms() { 
#if defined(_WIN32)
	return ( GetTickCount() );
#else
	timeval tv;
	gettimeofday( &tv, NULL );
	return ( u32(tv.tv_sec)*1000 + u32(tv.tv_usec)/1000 );
#endif
}

// Handle wrapping
inline u32 duration( u32 before, u32 now ) { 
	return ( now >= before ) ? ( now - before ) : ( now + ( 0xffffffff - before ) + 1 ); 
}

/*
	Simple delay mechanism
*/

struct delay {
	delay( u32 interval ) : mLastMs(0), mInterval(interval) { }
	bool poll() { 
		mNow = ( currentms() );
		mDuration = ( duration( mLastMs, mNow ) );
		if ( mDuration < mInterval )
			return ( false );
		mLastMs = ( mNow );
		return ( true );
	}
	u32 now() const { return ( mNow ); }
	template< class type > type durationseconds() const { return type(type(mDuration)/type(1000)); }

protected:
	u32 mLastMs, mInterval, mDuration, mNow;
};


struct ratemeasure {
	ratemeasure() : mTotal(0), mSum(0), mRate(0), mDelay(1000) {}
	float rate() { return ( update(0) ); }
	u32 total() const { return ( mTotal ); }

	float update( u32 amount ) {
		mSum += ( amount );
		if ( mDelay.poll() ) {
			mRate = ( ( 0.85f * float(mSum) / mDelay.durationseconds<float>() ) + mRate * 0.15f );
			mSum = ( 0 );
		}
		mTotal += ( amount );
		return ( mRate );
	}

protected:
	u32 mTotal, mSum;
	float mRate;
	delay mDelay;
} UPLOAD, HEARTBEATS, LISTREQS;



/*
	Quick fifo linked list queue. Check count() before using head() and pophead()
*/

template< class type >
struct linkedlist {
	struct node {
		node( const type &item ) : mNext(NULL) { mItem = ( item ); }
		type mItem;
		node *mNext;
	};

	linkedlist() : mHead(NULL), mTail(NULL), mCount(0) {}
	~linkedlist() {
		while ( mHead ) {
			node *tmp = ( mHead );
			mHead = ( tmp->mNext );
			delete tmp;
		}
	}

	s32 count() { return ( mCount ); }
	type &head() const { return ( mHead->mItem ); }

	void pushtail( const type &item ) {
		node *add = new node(item);
		if ( !mHead )
			mHead = ( add );
		else
			mTail->mNext = ( add );
		mTail = ( add );
		++mCount;
	}

	// unsafe
	type pophead() {
		type value = ( mHead->mItem );
		node *tmp = ( mHead );
		mHead = ( tmp->mNext );
		delete tmp;
		if ( !mHead )
			mTail = ( NULL );
		--mCount;
		return ( value );
	}

protected:
	node *mHead, *mTail;
	s32 mCount;
};



/*
	IP and Server objects
*/

struct ipv4  {
	ipv4() : mInt(0) {}
	ipv4( const char *ip ) { mInt = inet_addr( ip ); }
	ipv4( const in_addr &a ) { memcpy( &mInt, &a, 4 ); }
	ipv4( u8 a, u8 b, u8 c, u8 d ) { mOctets[0] = a; mOctets[1] = b; mOctets[2] = c; mOctets[3] = d; }
	static ipv4 any() { return ( ipv4( 0, 0, 0, 0 ) ); }
	u32 hash() const { return ( hashint(mInt) ); }
	in_addr inaddr() const { return( *((in_addr *)&mInt) ); }
	const char *tostr() const { return( inet_ntoa( inaddr() ) ); }
	bool operator== ( const ipv4 &b ) const { return ( mInt == b.mInt ); }
	u8 &operator[] ( u32 idx ) { return ( mOctets[idx] ); }
protected:
	union {
		u8 mOctets[4];
		u32 mInt;
	};
};

struct server {
	server() {}
	server( ipv4 ip, unsigned short port ) : mIP(ip), mPort(port) {}
	u32 hash() const { return ( mIP.hash() ^ hashint(mPort) ); }
	const ipv4 &ip() const { return ( mIP ); }
	u16 port() const { return ( mPort ); }
	static server random() { return ( server( ipv4(192,u8(rand()),u8(rand()),u8(rand())), 28001 ) ); }
	bool operator== ( const server &b ) const { return ( ( mIP == b.mIP ) && ( mPort == b.mPort ) ); }
	sockaddr_in tosockaddr() const {
		sockaddr_in to;
		memset( &to, 0, sizeof( to ) );
		to.sin_addr = ( ip().inaddr() );
		to.sin_port = ( htons(port()) );
		to.sin_family = ( AF_INET );
		return ( to );
	}
protected:
	ipv4 mIP;
	unsigned short mPort;
};

struct serverkeytool {
	template< class type > unsigned int hash( const type &a ) const { return ( a.hash() ); }
	template< class type > bool compare( const type &a, const type &b ) const { return ( a == b ); }
};


/*
	"Rate limited" round robinish UDP packet sender with a queue per connection
*/

struct packet {
	packet( const server &to, const u8 *buffer, u32 len ) : mTo(to), mLen(len) { 
		mBuffer = new u8[ len ]; 
		memcpy( mBuffer, buffer, len );
	}
	~packet() { delete mBuffer; }
	
	int send( int socket ) { 
		sockaddr_in to = ( mTo.tosockaddr() );
		int bytes = ( sendto( socket, (const char *)mBuffer, mLen, 0, (const sockaddr *)&to, sizeof( to ) ) ); 
		if ( bytes > 0 )
			UPLOAD.update( bytes + UDP_HEADER_SIZE );
		return ( bytes );
	}

protected:
	server mTo;
	u8 *mBuffer;
	u32 mLen;
};

struct udpqueue {
	typedef linkedlist<packet*> packetlist;
	typedef HashTable< server, packetlist*, serverkeytool > svmapper;
	typedef svmapper::Iterator sviterator;

	udpqueue() : mCompactDelay(5000), mFlushDelay(MASTER_INTERVAL_WAKE) {}

	~udpqueue() {
		sviterator iter = ( mMapper.Begin() ), end = ( mMapper.End() );
		for ( ; iter != end; ++iter )
			deletelist( iter.value() );
	}

	void deletelist( packetlist *list ) {
		while ( list->count() )
			delete list->pophead();
		delete list;
	}

	void queuepacket( const server &to, const u8 *buffer, u32 len ) {
		packetlist *&packets = mMapper[ to ];
		if ( !packets )
			packets = new packetlist();
		packets->pushtail( new packet( to, buffer, len ) );
	}

	void flushwrites( int socket ) {
		if ( !mFlushDelay.poll() )
			return;

		sviterator iter = ( mMapper.Begin() ), end = ( mMapper.End() );
		while ( iter != end ) {
			packetlist *packets = ( iter.value() );
			packets->head()->send( socket );
			delete packets->pophead();

			if ( !packets->count() ) {
				deletelist( packets );
				iter.Delete(); // delete advances iter
			} else {
				++iter;
			}
		}

		if ( mCompactDelay.poll() )
			mMapper.Compact();
	}

protected:
	delay mCompactDelay, mFlushDelay;
	svmapper mMapper;
};


/*
	UDP Socket
*/

struct socketudp {
	socketudp() : mSocket(-1) { }
	~socketudp() { if ( mSocket != -1 ) closesocket( mSocket ); }

	void flushwrites() { mQueue.flushwrites( mSocket ); }
	const server &from() const { return ( mFrom ); }
	int len() { return ( mFromLen ); }
	void queuepacket( const server &to, const u8 *buffer, u32 len ) { 
		mQueue.queuepacket( to, buffer, len ); 
	}

	int readfrom() {
		sockaddr_in from;
		socklen_t peersize = ( sizeof( from ) );
		mFromLen = recvfrom( mSocket, (char *)mBuffer, 1500, 0, (sockaddr *)&from, &peersize );
		mFrom = server( ipv4(from.sin_addr), ntohs(from.sin_port) );
		return ( mFromLen );
	}

	int senddata( const server &sv, const char *buffer, u32 len ) { 
		sockaddr_in to = ( sv.tosockaddr() );
		int bytes = sendto( mSocket, buffer, len, 0, (sockaddr *)&to, sizeof( to ) );
		if ( bytes > 0 )
			UPLOAD.update( bytes + UDP_HEADER_SIZE );

		return ( bytes ); 
	}

	bool trybind( ipv4 ip, u16 port ) {
		mSocket = int(socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP ));
		if ( mSocket < 0 )
			return ( false );
		
		unsigned long enable = 1, sndbuf = 262144;
		ioctlsocket( mSocket, FIONBIO, &enable );
		setsockopt( mSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&enable, sizeof(enable) );
		setsockopt( mSocket, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf) );
		
		sockaddr_in socksrc = server( ip, port ).tosockaddr();
		return ( bind( mSocket, (sockaddr*)&socksrc, sizeof( socksrc ) ) == 0 );
    }

	bool waitready( int ms ) {
		fd_set fdr;        
		FD_ZERO( &fdr ); 
		FD_SET( mSocket, &fdr );
		timeval timeout = { 0, 1000 * ms };
		return ( select( mSocket + 1, &fdr, NULL, NULL, &timeout ) > 0 );
	}

	const u8 &operator[] ( size_t idx ) const { return ( mBuffer[ idx ] ); }
	template< class type > const type &buf( size_t idx ) const { return ( *(type*)( mBuffer + idx ) ); }

protected:
	int mSocket;
	u8 mBuffer[ 1500 ];
	server mFrom;
	int mFromLen;
	udpqueue mQueue;
};



/*
	Packet builder
*/

struct packetbuilder {
	packetbuilder() : mBytes(0) {}
	const u8 *buffer() const { return ( mBuffer ); }
	u32 count() const { return ( mBytes ); }
	template< class type > type &ofs( size_t idx ) { return ( *(type*)( mBuffer + idx ) ); }
	packetbuilder &setpos( u32 index ) { mBytes = ( index ); return ( *this ); }
	template< class type > packetbuilder &operator<< ( type item ) { 
		*(type*)(mBuffer + mBytes) = item; 
		mBytes += sizeof( item ); 
		return ( *this ); 
	}
	packetbuilder &operator<<( const char *s ) {
		u8 *start = ( mBuffer + mBytes++ );
		while ( *s )
			mBuffer[ mBytes++ ] = u8( *s++ );
		*start = u8( mBuffer + mBytes - start - 1 );
		return ( *this );
	}
	void send( const server &sv, socketudp &sock ) { sock.queuepacket( sv, buffer(), count() ); }
	void sendnow( const server &sv, socketudp &sock ) { sock.senddata( sv, (const char *)buffer(), count() ); }

protected:
	u8 mBuffer[ 1500 ];
	u32 mBytes;
};



/*
	The Master Server
*/

struct masterserver {
	masterserver() { 
		mMotdHeader
			<< u8(0x10) << u8(0x06) << u8(0x01) << u8(0x01)	
			<< u8(0x00) << u8(0x00) << u8(0x00) << u8(0x66) 
			<< MASTER_FROM << MASTER_MOTD
			<< u8(0x00) << u8(0x00);
	}

	bool bind( const ipv4 &ip, u16 port ) { 
		return ( mSock.trybind( ip, port ) ); 
	}

	void process() {
		bool canread = mSock.waitready(MASTER_INTERVAL_WAKE);
		while ( canread && ( mSock.readfrom() > 0 ) ) {
			if ( mSock[0] != 0x10 )
				continue;

			switch ( mSock[1] ) {
				case 0x03: dumpservers( mSock.from() ); break; // server list req
				case 0x04: checkpending( mSock.from() ); break; // ping response, check for pending entry
				case 0x05: processheartbeat( mSock.from() ); break; // tribes server heartbeat			
				
				// generate random addresses for realistic hashtable loads + bypass penalties
				//case 0x03: dumpservers( server::random() ); break; 
				//case 0x05: processheartbeat( server::random() ); break;
			}
		}

		mServers.checkfilter();
		mPending.checkfilter();
		mSpam.checkfilter();
		mSock.flushwrites();
	}

	void registerserver( const server &sv, u32 timestamp ) {
		mServers.tryaddorupdate( sv, timestamp );
	}

	int servercount() const {
		return ( mServers.Count() );
	}

protected:
	/*
		IP limited server table, server=>timestamp
	*/
	struct iplimitedtable : public HashTable< server, u32, serverkeytool > {
		iplimitedtable() : mDelay(MASTER_SERVER_CHECK_INTERVAL) {}

		void checkfilter() { if ( mDelay.poll() ) Filter( *this ); }

		// called by HashTable.Filter for every element in the table
		bool operator() ( server &sv, u32 &timestamp ) {
			if ( duration( timestamp, mDelay.now() ) < MASTER_SERVER_TIMEOUT )
				return ( true );
			if ( !--mIpCounts[ sv.ip() ] )
				mIpCounts.Delete( sv.ip() );
			return ( false );
		}

		// add a server to the table, fails if ip limit is reached, updates if it already exists
		bool tryaddorupdate( const server &sv, u32 timestamp ) {
			if ( tryupdate( sv, timestamp ) )
				return ( true );

			u32 &ipcount = mIpCounts[ sv.ip() ];
			if ( ipcount >= MASTER_SERVER_MAXIPS )
				return ( false );

			Insert( sv, timestamp );
			++ipcount;
			return ( true );
		}

		// update the server if it exists
		bool tryupdate( const server &sv, u32 timestamp ) { 
			u32 *temp = ( Find( sv ) );
			if ( temp )
				*temp = ( timestamp );
			return ( temp != NULL );
		}

	protected:
		delay mDelay;
		HashTable< ipv4, u32, serverkeytool > mIpCounts;
	};

	/*
		Penalty table, IP=>penalty
	*/
	struct spamtable : public HashTable< ipv4, s32, serverkeytool > {
		spamtable() : mDelay(MASTER_PENALTY_CHECK_INTERVAL) {}
		bool addpenalty( const server &sv, s32 amount ) { 
			s32 &penalty = InsertUnique( sv.ip(), 0 );
			penalty = Min( penalty + amount, MASTER_SPAM_PENALTYCAP );
			return ( penalty < MASTER_SPAM_BANPENALTY );
		}
		void checkfilter() { if ( mDelay.poll() ) Filter( *this ); }
		bool operator() ( ipv4 &ip, s32 &penalty ) { 
			penalty -= (MASTER_PENALTY_CHECK_INTERVAL/1000);
			return ( penalty > 0 );
		}
	protected:
		delay mDelay;
	};

	/*
		Pending challenge table, server=>timestamp
	*/
	struct pendingtable : public HashTable< server, u32, serverkeytool > {
		pendingtable() : mDelay(MASTER_PENDING_CHECK_INTERVAL) {}
		void checkfilter() { if ( mDelay.poll() ) Filter( *this ); }
		bool operator() ( server &sv, u32 &timestamp ) { 
			return ( duration( timestamp, mDelay.now() ) < MASTER_PENDING_TIMEOUT ); 
		}
	protected:
		delay mDelay;
	};


	/*
		checkpending
		
		See if we have a pending server with this address, that it hasn't timed
		out, and that it has the correct challenge

		The challenge is a hash of the server address and the timestamp so we don't
		have to store a seperate challenge
	*/
    void checkpending( const server &sv ) {
		if ( mSock.len() < 6 )
			return;

		// do we have a pending server with this address
		u32 *timestamp = mPending.Find( sv );
		if ( !timestamp || duration( *timestamp, currentms() ) > MASTER_PENDING_TIMEOUT )
			return;
			
		// valid challenge?
		if ( mSock.buf<u16>(4) == u16(sv.hash() ^ hashint(u32(*timestamp))) )
			registerserver( sv, currentms() );
	}

	/*
		dumpservers

		Sends the server list to the specified address. This is a little
		convoluted to handle arbitrary servers per packet, maximum packet
		sizes, and sending out single servers
	*/
	void dumpservers( const server &sv ) {
		if ( !mSpam.addpenalty( sv, MASTER_SPAM_LISTPENALTY ) )
			return;

		// init packet with preset motd
		packetbuilder buf = mMotdHeader;

		// servercount has to be a pointer because it's position changes
		u8 &PACKETON = buf.ofs<u8>(2), &PACKETTOT = buf.ofs<u8>(3);
		u8 *SERVERCOUNT = &buf.ofs<u8>( buf.count() - 1 );

		// packet key/challenge
		buf.ofs<u16>(4) = ( mSock.len() >= 6 ) ? mSock.buf<u16>(4) : 0x6666;

		// if this is anything other than 0xff, they're requesting a single packet
		u8 packetreq = ( mSock.len() >= 3 ) ? mSock.buf<u8>(2) : 0xff;
		bool singlepacket = ( packetreq != 0xff );

		// compute how many servers we can pack in to the initial and subsequent packets
		int bytes_left = ( MASTER_PACKET_SIZE - buf.count() );
		int servers_left = ( ( bytes_left - 1 ) / 7 ) + 1;
		int remaining_servers = ( Max( mServers.Count() - servers_left, 0 ) );
		if ( remaining_servers )
			PACKETTOT += u8( ( remaining_servers * 7 - 1 ) / ( MASTER_PACKET_SIZE - 10 ) ) + 1;

		bool has_servers = true; // initial packet needs to be sent
		iplimitedtable::Iterator iter = ( mServers.Begin() ), end = ( mServers.End() );
		for ( ; iter != end; ++iter ) {
			has_servers = true;
			u16 port = ( iter.key().port() );
			buf << u8(6) << iter.key().ip() << u8(port&0xff) << u8(port>>8);

			++SERVERCOUNT[0];
			if ( buf.count() >= MASTER_PACKET_SIZE ) {
				if ( !singlepacket || ( packetreq == PACKETON ) )
					buf.send( sv, mSock );		

				if ( packetreq == PACKETON )
					break;

				buf.setpos( 8 ) << u8(0x00) << u8(0x00);
				SERVERCOUNT = &buf.ofs<u8>( 9 );
				++PACKETON;
				has_servers = false;
			}
		}

		// send the packet if we didn't fill it up
		if ( has_servers )
			buf.send( sv, mSock );

		LISTREQS.update(1);
	}

	/*
		processheartbeat

		Either update the server's timestamp, or send out a challenge
		that must be answered for the server to be registered
	*/
	void processheartbeat( const server &sv ) {
		if ( !mSpam.addpenalty( sv, MASTER_SPAM_HEARTBEATPENALTY ) )
			return;

		u32 now = currentms();

		// either add the heartbeat (if registered) or update the pending challenge
		if ( !mServers.tryupdate( sv, now ) ) {
			mPending[ sv ] = now;
			packetbuilder challenge;
			challenge << u8(0x10) << u8(0x03) << u8(0xff) << u8(0x00) << u16(sv.hash() ^ hashint(u32(now)));
			challenge.sendnow( sv, mSock );
		}

		HEARTBEATS.update(1);
	}

	iplimitedtable mServers;
	pendingtable mPending;
	spamtable mSpam;
	socketudp mSock;
	packetbuilder mMotdHeader;
};




/*
	Simple argument -> value mapper with type conversion
*/

struct args {
	args( int argc, const char *argv[] ) {
		const char **end = ( argv + argc );
		while ( argv != end ) {
			const char *arg = ( *argv++ );
			if ( *arg != '-' )
				continue;
			
			const char *param = ( ( argv != end ) && ( *argv[0] != '-' ) ) ? *argv++ : NULL;
			mHash[ arg ] = param;
		}
	}

	bool hasflag( const char *key ) const { return ( mHash.Find( key ) ) ? true : false; }

	template< class type > const args &mapto( const char *key, type &dest ) const {
		const char **value = mHash.Find( key );
		if ( value && *value )
			parse( *value, dest );
		return ( *this );
	}

	bool wantshelp() const { return ( hasflag( "-h" ) || hasflag( "--help" ) ); }

protected:
	template< class type > void parse( const char *value, type &dest ) const { dest = ( type(atoi( value )) ); }
	void parse( const char *value, ipv4 &dest ) const { dest = ( ipv4( value ) ); }
	void parse( const char *value, const char *&dest ) const { dest = ( value ); }

	HashTable< const char*, const char* > mHash;
};



/*
	Main
*/

namespace signalhandler {
	bool shouldquit = false;

#if defined(_WIN32)
	BOOL WINAPI handler( DWORD dwCtrlType ) {
		shouldquit = ( dwCtrlType == CTRL_C_EVENT );
		return ( shouldquit );
	}

	void Init() { 
		SetConsoleCtrlHandler( handler, TRUE ); 
	}
#else
	void handler( int sig ) {
		shouldquit = ( true );
		signal( sig, SIG_DFL );
	}

	void Init() { 
		signal( SIGHUP, handler );
		signal( SIGINT, handler );
		signal( SIGQUIT, handler );
		signal( SIGUSR1, handler );
		signal( SIGTERM, handler );
	}
#endif
};

void upandfront() { 
#if defined(_WIN32)
	HANDLE h = GetStdHandle( STD_OUTPUT_HANDLE );
	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo( h, &info );
	info.dwCursorPosition.X = 0;
	info.dwCursorPosition.Y -= 1;
	SetConsoleCursorPosition( h, info.dwCursorPosition );
#else
	printf( "\033[0G\033[1A" ); 
#endif
}

int main( int argc, const char *argv[] ) {
	signalhandler::Init();
	srand( int(currentms()) );
	sethashseed( rand() * rand() );

	puts( "Tribes 1 Master Server\nBy Andrew (Ctrl-C to quit)\n" );

	args parms( argc, argv );
	if ( parms.wantshelp() ) {
		puts( "Usage: t1master [options]\n" );
		puts( "  -bind <ip>            Bind the server to the specified IP. Default 0.0.0.0" );
		puts( "  -port <#>             Listen on the specified port. Default 28000" );
		puts( "  -from \"<from>\"        Who the MOTD is from. Must be quoted to preserve spaces" );
		puts( "  -motd \"<message>\"     Message of the day. Must be quoted to preserve spaces" );
		puts( "  -svperip <#>          Maximum servers allowed per ip. Default 5" );
		return ( 0 );
	}

	ipv4 bind_ip = ipv4::any();
	u16 bind_port = ( 28000 );
	
	parms	.mapto( "-bind", bind_ip )
			.mapto( "-port", bind_port )
			.mapto( "-motd", MASTER_MOTD )
			.mapto( "-from", MASTER_FROM )
			.mapto( "-svperip", MASTER_SERVER_MAXIPS );

#if defined(_WIN32)
	WSADATA wsadata;
	WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

	masterserver master;
	if ( !master.bind( bind_ip, bind_port ) ) {
		printf( "bind failed %d (%s:%d)\n", errno,
			bind_ip.tostr(), bind_port );
		return ( -1 );
	}

	/*
	// dummy servers for testing
	for ( int i = 0; i < 20000; i++ )
		master.registerserver( server::random(), currentms() );
	*/


	delay info(1000);
	while ( !signalhandler::shouldquit ) {
		master.process();
		if ( info.poll() ) {
			printf( "%4d Servers, %2.2f Reqs/s, %2.2f Heartbeats/s, %6.2f kb/s Up               \n",
				master.servercount(), LISTREQS.rate(), HEARTBEATS.rate(), UPLOAD.rate()/1024.0f );
			upandfront();
		}
	}


#if defined(_WIN32)
	WSACleanup();
#endif
	printf( "\n\nDone.\n" );
	return ( 0 );
}
