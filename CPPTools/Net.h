#pragma once


#ifndef _NET_H
#define _NET_H

#ifdef _NET_SMALL_BUF
#define BUFSIZE 512
#define BUF_2_MAX 2048
#else
#define BUFSIZE 1073741824		// 1 GiB
#define BUF_2_MAX 1073741824	// 1 GiB
#endif

#define WIN32_LEAN_AND_MEAN

// Ping flag tells the recieving host to drop the current ulong_64b, as it is sent to check if the connection is still alive
#define FLAG_PING (ulong_64b)-1
#define FLAG_PART (ulong_64b)-2
#define FLAG_NPRT (ulong_64b)-3

#include "Crypto.h"
#include "ArchAbstract.h"

#include <winsock2.h>
#include <vector>
#include <thread>
#include <functional>
#include <future>


namespace IO {

	class AsyncKeys {
	private:
		std::future<Crypto::RSA::KeyData*> gen;
		Crypto::RSA::KeyData* keys;
		AsyncKeys* chainKeys;
		volatile bool done;
		bool suppressDelete;
		bool chain;
	public:
		AsyncKeys();
		AsyncKeys(Crypto::RSA::KeyData* predef);
		AsyncKeys(AsyncKeys*);
		~AsyncKeys();
		Crypto::RSA::KeyData* get();
	};

	enum CryptoLevel { None, Prefer, Force };

	struct Packet {
		ulong_64b size;
		char packetUID;
		char* message;
	};

	struct PartialPacket {
		ulong_64b size;
		char* message;
	};

	class NetServer;
	class NetClient {
		friend class NetServer;					// Allow NetServer to access all members of NetClient

	private:
		volatile bool _open;					// Whether or not connection is open
		bool canWrite;							// Whether or not writing to peer is possible
		bool noThread;							// Whether or not reading incoming data should be / is being done in a separate thread
		bool scheduleTerminate = false;
		std::vector<char> rBuf;
		CryptoLevel preferEncrypted = CryptoLevel::None;// Whether or not the socket should attempt to request an encrypted channel
		bool encrypted = false;					// Whether or not negotiation determined the use of an encrypted channel
		bool firstMessage = true;				// Whether or not negotiation has yet ocurred
		ulong_64b fm_neg_size;					// First message negotiation size
		bool fm_neg_hasLevel = false;			// First message has crypto level
		bool fm_neg_hasSize = false;			// Got negotiation size from first message
		bool startNegotiate = false;			// Whether or not to initiate negotiation
		char expectedNextPUID = 0;
		char remotePUID = 0;
		std::vector<char>* sparse;
		std::vector<Packet>* outPacketBuf;
		AsyncKeys *keyData;				// Client's keysets (if using encryption)
		CryptoPP::RSAFunction pK;				// Remote host's public key (if using encryption)

		NetClient(char*, char*, CryptoLevel, bool); // Underlying setup for regular constructors
		NetClient(SOCKET, bool, CryptoLevel, bool);// Special setup constructor
		NetClient(SOCKET, bool, AsyncKeys*, CryptoLevel = CryptoLevel::None, bool = false);// Create wrapper for existing socket
		void sharedSetup(bool);					// Setup function for all constructor
		bool _write(char*, ulong_64b);			// Internal write function. Doesn't do any of the fancy auto encryption: just raw write...
		bool writeBufferedPackets();			// Flushes and deletes buffer
		void update();							// Read incoming data and store in buffers
	protected:
		std::vector<std::pair<char*, std::pair<ulong_64b, char*>*>*> associatedData;
		std::thread listener;					// Incoming data listener (optional)
		SOCKET _socket;							// Underlying socket used for communication
		std::vector<Packet>* packets;			// Basically a set containing a backlog of unprocessed data. Will oly be used if event handler doesn't exist


		std::function<void(NetClient*, Packet)> evt;	// New data event handler
		std::function<void()> onDestroy;		// Event handler called when NetClient object is destroyed
	public:
		bool autoPing = true;					// Whether or not client should actively check connection state
		bool autoDelete = false;
		time_t commTime;						// Latest time a transaction occurred
		NetClient(char* ipAddr, char* port, CryptoLevel = CryptoLevel::None);// Standard constructor for creating connection
		NetClient(char* ipAddr, char* port, AsyncKeys*, CryptoLevel);// Standard constructor for creating connection with predefined keys
		~NetClient();
		bool close();
		void closeWrite();
		bool isEncrypted();
		size_t getBOPCount();					// Should return the amount of buffered packets to be sent to server
		bool write(void* message, ulong_64b size);
		bool write(char* message);
		Packet read();
		void setEventHandler(std::function<void(NetClient*, Packet)>);// Register a callback that is guaranteed to be called when the socket has at least one unprocessed packet
		void setOnDestroy(std::function<void()>);
		std::pair<ulong_64b, char*> getValue(const char* name, bool copy = true);
		char* getStrValue(const char* name, bool copy = true);
		void setValue(const char* name, std::pair<ulong_64b, char*> value, bool copy = true, bool del = true);
		void setValue(const char* name, char* data, bool copy = true, bool del = true);
		bool removeValue(const char* name, bool del = true);
		bool containsKey(const char* name);
		bool isOpen();
		ulong_64b available();
		bool ping();							// Check if connection is alive by pinging remote host
	};

	class NetServer {
		friend class NetClient;
	private:
		CryptoLevel pref;
		AsyncKeys *keyData;				// Server's keysets (if using encryption)
		std::function<void()> onDestroy;
		volatile bool _open;
		bool scheduleTerminate = false;

		void sharedSetup(char* port, std::function<bool(NetClient*)> f);
		void updateClients();
	protected:
		std::thread clientListener;
		std::vector<std::function<bool(NetClient*)>>* handlers;
		std::vector<NetClient*>* clients;
	public:
		std::function<bool(NetClient*)> timeoutHandler;
		NetServer(char* port, std::function<bool(NetClient*)> = nullptr, CryptoLevel = CryptoLevel::None);
		NetServer(char* port, std::function<bool(NetClient*)>, AsyncKeys&, CryptoLevel);
		~NetServer();
		bool isOpen();
		CryptoLevel getCryptoPreference();
		void addHandler(std::function<bool(NetClient*)>);
		void clearHandlers();
		void setOnDestroy(std::function<void()>);
		bool close();
		void setAutoPing(bool);
		ulong_64b getClientCount();
		NetClient* at(ulong_64b);
	};



	// Partial data stream management
	static const auto STREAM_DELIMIT = FLAG_PART;
	static const auto STREAM_PAUSE   = FLAG_NPRT;
	static const auto STREAM_ATTRIB  = (const char*) "$PartialNetworkStream$ACTIVE";
	static const auto STREAM_BUFMIN  = 32;


	/*
	  START represents the beginning of a partial message
	  PAUSE represents a pause in the partial stream in which a full (unrelated) message is being sent
	  RESUME tells dev that the partial stream is being resumed (from a full-write state)
	  END   represebts the end of a partial message
	  DATA  represents the the supplied data isn't metadata
	*/
	enum PartialDataState { START, PAUSE, RESUME, END, DATA };

	/*
	  PARTIAL tells you that the stream is currently accepting partial data packets
	  PAUSE means that the client is set to accept a partial stream, but has been specifically paused to accept a full message
	  FULL means that the client is interpreting messages as full message blocks
	*/
	enum PartialCommState { COMM_FULL, COMM_PARTIAL, COMM_PAUSE };


	class PartialNetworkStream : public std::ostream{
	protected:
		const bool permissive;
		bool open;
		std::vector<char>* buffer;
		NetClient& client;

		bool check(PartialCommState state);
		void sendState(PartialCommState state);
	public:
		PartialNetworkStream(NetClient&, bool = false, bool = true);
		~PartialNetworkStream();

		void endPartial();
		void startPartial();
		PartialCommState getCommState();
		void write(char*, std::streamsize, bool = false);
		void writeNonPartial(char*, std::streamsize);
		void flush();

		static PartialDataState accept(NetClient& cli, Packet& pkt);
		static bool stateIs(NetClient& cli, PartialCommState state);

	};
}

#endif