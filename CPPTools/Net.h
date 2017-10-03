#pragma once


#ifndef _NET_H
#define _NET_H

#ifdef _NET_SMALL_BUF
#define BUFSIZE 512
#define BUF_2_MAX 2048
#else
#define BUFSIZE 16384
#define BUF_2_MAX 16384
#endif

#define WIN32_LEAN_AND_MEAN

// Ping flag tells the recieving host to drop the current ulong_64b, as it is sent to check if the connection is still alive
#define FLAG_PING (ulong_64b)-1

#include "Crypto.h"
#include "ArchAbstract.h"

#include <winsock2.h>
#include <vector>
#include <thread>
#include <functional>


namespace IO {

	enum CryptoLevel { None, Prefer, Force };

	class NetServer;
	class NetClient;
	class NetPacket;
	class SparseNetPacket;

	class NetPacketBuilder {
	protected:
		bool sparse, hasBuilt;
		NetPacket* _build;
		const ulong_64b sparseSize;

	public:
		NetPacketBuilder(char PUID, ulong_64b sparseSize = BUFSIZE);			// Auto-generate target size
		virtual ~NetPacketBuilder();											// Destructor. Should remove any packets

		ulong_64b size();														// Status: Current write size

		NetPacketBuilder& append(char datum);									// Write a single char
		NetPacketBuilder& append(char *data, ulong_64b size);					// Write a block of data
		NetPacketBuilder& append(char *data);									// For writing strings (or any string of data wherein the length can be determined by finding a null-terminator)

		NetPacket* build();														// Generate packet
	};

	class NetPacket {
		friend class NetPacketBuilder;
		friend class SparseNetPacket;
		friend class NetServer;
		friend class NetClient;
	private:
		ulong_64b _size;
		NetPacket(char PUID);													// Special builder constructor
		NetPacket(ulong_64b &size, char PUID, ulong_64b sparseSize, char* msg);	// Special sparse constructor

	protected:
		char *message;															// The actual message

		virtual void write(char* toWrite, ulong_64b writeCount);				// Special builder function
		virtual void write(char toWrite);										// Special builder function

	public:
		const ulong_64b& size;													// Immutable value denoting size of message
		const char PUID;														// Immutable value denoting "unique", incremental id of this message

		NetPacket(ulong_64b size, char PUID, char *message);					// Standard constructor
		virtual ~NetPacket();													// Destructor for packet

		virtual char* __cdecl read(ulong_64b readCount, ulong_64b startIndex);	// Read a block of data
		virtual char* __cdecl read(ulong_64b readCount);						// Read a block of data starting at index 0
		virtual char* __cdecl copyMessage();									// Get a copy of entire message
	};
	
	// Sparse packet. This should be for messages >BUFSIZE
	class SparseNetPacket : public NetPacket {
		friend class NetPacketBuilder;
		friend class NetServer;
		friend class NetClient;
	private:
		ulong_64b sparseSize;

	protected:
		ulong_64b sparseCount;
		char** sparseFull;
		const ulong_64b maxPerPacket;

		SparseNetPacket(ulong_64b size, char PUID, ulong_64b sparseSize, char* message, ulong_64b maxPerPacket);
		SparseNetPacket(char PUID, ulong_64b maxPerPacket);

		virtual void write(char * toWrite, ulong_64b writeCount);
		virtual void write(char toWrite);

	public:
		virtual ~SparseNetPacket();
		virtual char* __cdecl read(ulong_64b readCount, ulong_64b startIndex);
		virtual char* __cdecl copyMessage();
	};





	struct Packet {
		ulong_64b size;
		char packetUID;
		char* message;
	};

	/*
	// First sparse packet implementation. All future ones should follow this model

	typedef char* SparsePacket;
	struct SparsePacketSet {
		ulong_64b lastSize;
		ulong_64b sparseCount;
		SparsePacket* sparse;
		SparsePacket last;
	};
	*/

	class NetClient {
		friend class NetServer;					// Allow NetServer to access all members of NetClient

	private:
		volatile bool _open;					// Whether or not connection is open
		bool canWrite;							// Whether or not writing to peer is possible
		bool noThread;							// Whether or not reading incoming data should be / is being done in a separate thread
		char rBuf[BUFSIZE];						// Recieve buffer
		CryptoLevel preferEncrypted = CryptoLevel::None;// Whether or not the socket should attempt to request an encrypted channel
		bool encrypted = false;					// Whether or not negotiation determined the use of an encrypted channel
		bool firstMessage = true;				// Whether or not negotiation has yet ocurred
		ulong_64b fm_neg_size;
		bool fm_neg_hasLevel = false;
		bool fm_neg_hasSize = false;
		bool startNegotiate = false;
		char expectedNextPUID = 0;
		char remotePUID = 0;
		std::vector<char>* sparse;				// DEPRECATED

		ulong_64b expect = 0;
		NetPacketBuilder* builder = nullptr;

		std::vector<Packet>* outPacketBuf;
		Crypto::RSA::KeyData keys;				// Client's keysets (if using encryption)
		CryptoPP::RSAFunction pK;				// Remote host's public key (if using encryption)

		NetClient(SOCKET, bool, CryptoLevel, bool);// Special setup constructor
		NetClient(SOCKET, bool, Crypto::RSA::KeyData&, CryptoLevel = CryptoLevel::None, bool = false);// Create wrapper for existing socket
		void sharedSetup();						// Setup function for all constructor
		bool _write(char*, ulong_64b);			// Internal write function. Doesn't do any of the fancy auto encryption: just raw write...
		bool writeBufferedPackets();			// Flushes and deletes buffer
		void update();							// Read incoming data and store in buffers
		bool ping();							// Check if connection is alive by pinging remote host
	protected:
		std::thread listener;					// Incoming data listener (optional)
		SOCKET _socket;							// Underlying socket used for communication
		std::vector<Packet>* packets;			// Basically a set containing a backlog of unprocessed data. Will oly be used if event handler doesn't exist
		std::function<void(NetClient*, Packet)> evt;	// New data event handler
		std::function<void()> onDestroy;		// Event handler called when NetClient object is destroyed
	public:
		time_t commTime;						// Latest time a transaction occurred
		std::vector<char*> associatedData;
		NetClient(char* ipAddr, char* port, CryptoLevel = CryptoLevel::None);// Standard constructor for creating connection
		~NetClient();
		bool close();
		void closeWrite();
		bool isEncrypted();
		size_t getBOPCount();					// Should return the amount of buffered packets to be sent to server
		bool write(void* message, ulong_64b size);
		bool write(char* message);
		Packet read();
		void setEventHandler(std::function<void(NetClient*, Packet)>);		// Register a callback that is guaranteed to be called when the socket has at least one unprocessed packet
		void setOnDestroy(std::function<void()>);
		bool isOpen();
		ulong_64b available();
	};
	class NetServer {
		friend class NetClient;
	private:
		CryptoLevel pref;
		Crypto::RSA::KeyData keys;				// Server's keysets (if using encryption)

		std::function<void()> onDestroy;
		volatile bool _open;
		void updateClients();
	protected:
		std::thread clientListener;
		std::vector<std::function<bool(NetClient*)>>* handlers;
		std::vector<NetClient*>* clients;
	public:
		std::function<bool(NetClient*)> timeoutHandler;
		NetServer(char* port, std::function<bool(NetClient*)>, CryptoLevel);
		~NetServer();
		bool isOpen();
		CryptoLevel getCryptoPreference();
		void addHandler(std::function<bool(NetClient*)>);
		void clearHandlers();
		void setOnDestroy(std::function<void()>);
		bool close();
	};
}

#endif