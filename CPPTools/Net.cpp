#include "Net.h"
#include "Support.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <ws2tcpip.h>

namespace IO {

	char* __cdecl copy(char* data, ulong_64b size) { // Convenience function for copying data
		char* c = new char[size];
		memcpy(c, data, size);
		return c;
	}

	NetPacketBuilder::NetPacketBuilder(char PUID, ulong_64b sparseSize) :
		sparseSize(sparseSize<2?BUFSIZE:sparseSize),
		sparse(false),
		hasBuilt(false),
		_build(new NetPacket(PUID))
	{

	}
	NetPacketBuilder::~NetPacketBuilder() {
		if (!hasBuilt) delete[] _build;
	}

	ulong_64b NetPacketBuilder::size() { return _build->size; }

	NetPacketBuilder& NetPacketBuilder::append(char datum) { return append(&datum, 1); }
	NetPacketBuilder& NetPacketBuilder::append(char *data, ulong_64b size) {
		if (!sparse && ((_build->size + size) > sparseSize)) {
			SparseNetPacket* snp = new SparseNetPacket(_build->size, _build->PUID, _build->size, _build->message, sparseSize);
			delete _build;
			_build = snp;
		}
		_build->write(data, size);
		return *this;
	}
	NetPacketBuilder& NetPacketBuilder::append(char *data) { return append(data, strlen(data)); }
	NetPacket* NetPacketBuilder::build() { hasBuilt = true;  return _build; }



	NetPacket::NetPacket(char PUID) : _size(0), size(_size), PUID(PUID) {}

	NetPacket::NetPacket(ulong_64b size, char PUID, char *msg) : _size(size), size(_size), PUID(PUID) {
		// Copy message to protected field (not reference)
		this->message = copy(msg, size);
	}

	NetPacket::NetPacket(ulong_64b &size, char PUID, ulong_64b sparseSize, char* msg) : _size(sparseSize), size(size), PUID(PUID) {
		this->message = copy(msg, sparseSize);
	}

	NetPacket::~NetPacket() {
		delete[] message;
	}

	void NetPacket::write(char* toWrite, ulong_64b writeCount) {
		char* newMsg = new char[_size + writeCount];
		memcpy(newMsg, message, _size);
		delete[] message;
		memcpy(newMsg + _size, toWrite, writeCount);
		message = newMsg;
		_size += writeCount;
	}
	void NetPacket::write(char toWrite) { write(&toWrite, 1); }

	// Copies a subset of the full message and returns to caller: starting at index "startIndex" of message and ending at index "startIndex + readCount"
	char* __cdecl NetPacket::read(ulong_64b readCount, ulong_64b startIndex) {
		if ((readCount + startIndex) > _size) throw new std::exception("Read index out of bounds for start index "+startIndex);
		char* read = new char[readCount];
		memcpy(read, message+startIndex, readCount);
		return read;
	}
	// Copies "readCount" chars from message starting at index 0
	char* __cdecl NetPacket::read(ulong_64b readCount) { return read(readCount, 0); }

	// Returns a copy of the entire message
	char* __cdecl NetPacket::copyMessage() { return read(_size); }



	SparseNetPacket::SparseNetPacket(ulong_64b size, char PUID, ulong_64b sparseSize, char* message, ulong_64b maxPerPacket) :
		NetPacket(size, PUID, sparseSize, message+(size-sparseSize)),	// Base constructor
		maxPerPacket(maxPerPacket),										// Set max sparse packet size
		sparseCount((size - (size%maxPerPacket)) / maxPerPacket),		// Set current amount of sparse packets
		sparseSize(size)
	{
		sparseFull = new char*[sparseCount];
		for (ulong_64b b = 0; b < sparseCount; ++b) sparseFull[b] = copy(message + (b*maxPerPacket), maxPerPacket); // Split given message into sparse blocks
	}
	SparseNetPacket::SparseNetPacket(char PUID, ulong_64b maxPerPacket) : SparseNetPacket(0, PUID, 0, nullptr, maxPerPacket) {}



	SparseNetPacket::~SparseNetPacket() {
		for (ulong_64b b = 0; b < sparseCount; ++b) delete[] sparseFull[b];
		delete[] sparseFull;
	}

	void SparseNetPacket::write(char* toWrite, ulong_64b writeCount) {
		ulong_64b actualWriteCount = maxPerPacket - _size;

		if (writeCount >= actualWriteCount) {


			char** c = new char*[++sparseCount];
			memcpy(c, sparseFull, sizeof(sparseFull)*(sparseCount - 1));
			delete[] sparseFull;
			sparseFull = c;


			sparseFull[sparseCount - 1] = new char[maxPerPacket];
			memcpy(sparseFull[sparseCount - 1], message, _size);
			memcpy(sparseFull[sparseCount - 1] + _size, toWrite, actualWriteCount);
			delete[] message;

			_size = 0;
			message = new char[0];
			write(toWrite+actualWriteCount, writeCount-actualWriteCount);
			sparseSize += actualWriteCount;
		}
		else {
			char* msg = new char[_size+writeCount];
			memcpy(msg, message, _size);
			memcpy(msg + _size, toWrite, writeCount);
			delete[] message;
			message = msg;
			sparseSize += writeCount;
			_size = writeCount;
		}
	}
	void SparseNetPacket::write(char toWrite) { write(&toWrite, 1); }

	char* __cdecl SparseNetPacket::read(ulong_64b readCount, ulong_64b startIndex) {
		if ((readCount + startIndex) > sparseSize) throw new std::exception("Index out of bounds!");
		char* read = new char[readCount];


		// Get the first sparse packet to read from
		ulong_64b sparseIdx = (startIndex - (startIndex%maxPerPacket)) / maxPerPacket;

		// Adjust read index to be within bounds of the packet we will read from
		startIndex = startIndex%maxPerPacket;

		if ((sparseIdx > sparseCount) || ((sparseIdx == sparseCount) && startIndex >= _size))					// Make sure we're reading a valid range of data
			throw new std::exception("Index out of bounds!");

		ulong_64b count = 0;
		while (count < readCount) {
			ulong_64b rc = min(readCount - count, maxPerPacket - startIndex);									// Calculate amount of bytes to read by assessing whether or not we can read the entire packet or not
			memcpy(read + count, ((sparseIdx<sparseCount)?sparseFull[sparseIdx++]:message) + startIndex, rc);	// Check if we're reading from the last packet (partially populated, non-sparse message) or not
			if (startIndex != 0) startIndex = 0;																// If-statement to help with processor cache prediction: basically optimize away this statement after first call
			count += rc;																						// Increment read count
		}

		return read;
	}

	// Returns a copy of the entire message
	char* __cdecl SparseNetPacket::copyMessage() { return read(sparseSize, 0); }





	bool cryptoLevelsAreCompatible(CryptoLevel l1, CryptoLevel l2) {
		return !(((l1 == CryptoLevel::None) && (l2 == CryptoLevel::Force)) || ((l2 == CryptoLevel::None) && (l1 == CryptoLevel::Force)));
	}

	char* __cdecl readSparse(std::vector<char>* sparse, ulong_64b rSize, bool pop = true) {
		if (sparse->size() < rSize) throw new _exception(); // This should never happen if function is used correctly
		char* c = new char[rSize];
		for (ulong_64b b = 0; b < rSize; ++b) c[b] = sparse->at(b);
		if (pop) sparse->erase(sparse->begin(), sparse->begin() + rSize);
		return c;
	}

	void flushPrecedingPings(std::vector<char>* sparse) {
		while (sparse->size() >= sizeof(ulong_64b)) {
			ulong_64b size = 0;
			char* c = readSparse(sparse, sizeof(ulong_64b), false);
			memcpy(&size, c, sizeof(ulong_64b));
			delete[] c;
			if (size != FLAG_PING) return;
			else delete[] readSparse(sparse, sizeof(ulong_64b)); // If this block is a ping packet, remove it
		}
	}

	bool hasFullMessage(std::vector<char> *sparse) {
		if (sparse->size() < sizeof(ulong_64b)) return false;
		flushPrecedingPings(sparse);
		ulong_64b size = 0;
		char* c = readSparse(sparse, sizeof(ulong_64b), false);
		memcpy(&size, c, sizeof(ulong_64b));
		delete[] c;
		return sparse->size() >= (size + sizeof(ulong_64b));
	}

	void NetClient::sharedSetup() {
		if (preferEncrypted != CryptoLevel::None) keys = Crypto::RSA::rsa_gen_keys();
		packets = new std::vector<Packet>();
		sparse = new std::vector<char>();
		outPacketBuf = new std::vector<Packet>();
		_open = true;
		canWrite = true;
		evt = nullptr;
		char cryptoPref = static_cast<char>(preferEncrypted);
		commTime = time(nullptr);
		if (send(_socket, &cryptoPref, 1, 0) == SOCKET_ERROR) throw new _exception(); // Cannot establish connection :(
		if (!noThread) listener = std::thread([](NetClient& cli) { while (cli._open) { cli.update(); Sleep(25); } }, std::ref(*this)); // Setup separate thread for reading new data
	}

	NetClient::NetClient(char* ipAddr, char* port, CryptoLevel preferEncrypted) :
		commTime(time(nullptr)), preferEncrypted(preferEncrypted), startNegotiate(false)
	{
		_socket = INVALID_SOCKET;
		this->noThread = false;

		WSADATA wsaData;
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) throw new _exception();


		struct addrinfo *result = NULL, *ptr = NULL, hints;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		iResult = getaddrinfo(ipAddr, port, &hints, &result);

		if (iResult) throw new _exception();

		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
			if (_socket == INVALID_SOCKET) {
				throw new _exception();
			}

			// Connect to server.
			iResult = connect(_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				closesocket(_socket);
				_socket = INVALID_SOCKET;
				continue;
			}
			break;
		}

		freeaddrinfo(result);

		if (_socket == INVALID_SOCKET) throw new _exception();

		sharedSetup();
	}

	NetClient::NetClient(SOCKET wrap, bool noThread, Crypto::RSA::KeyData& keys, CryptoLevel preferEncrypted, bool startNegotiate) :
		commTime(time(nullptr)), preferEncrypted(preferEncrypted), startNegotiate(startNegotiate)
	{
		_socket = wrap;
		this->noThread = noThread;
		sharedSetup();
	}

	NetClient::~NetClient() {
		packets->clear();
		delete packets;
		sparse->clear();
		delete sparse;
		if (isOpen()) close();
	}
	bool NetClient::close() {
		bool result = !_open;
		_open = false;
		result &= (SOCKET_ERROR == shutdown(_socket, SD_BOTH));
		closesocket(_socket);
		return result;
	}
	void NetClient::closeWrite() {
		shutdown(_socket, SD_SEND);
		canWrite = false;
	}
	bool NetClient::ping() {
		int i;
		char* c = new char[sizeof(ulong_64b)];
		ulong_64b pingValue = FLAG_PING;
		memcpy(c, (const char*)&pingValue, sizeof(ulong_64b));
		for (ulong_64b wIdx = 0; wIdx < sizeof(ulong_64b); ++wIdx) {
			if ((i = send(_socket, c + wIdx, 1, 0)) == SOCKET_ERROR) return false;
			else if (i == 0) --wIdx;
		}
		commTime = time(nullptr);
		return true;
	}

	size_t NetClient::getBOPCount() { return firstMessage ? outPacketBuf->size() : 0; }

	bool NetClient::_write(char* message, ulong_64b size) {
		if (size==FLAG_PING) throw new _exception();	   // Max value is reserved for ping packet
		int i;
		char* c = new char[sizeof(ulong_64b)];
		memcpy(c, &size, sizeof(ulong_64b));
		for (ulong_64b wIdx = 0; wIdx < sizeof(ulong_64b); ++wIdx) {
			if ((i = send(_socket, c + wIdx, 1, 0)) == SOCKET_ERROR) return false;
			else if (i == 0) --wIdx;
		}
		for (ulong_64b wIdx = 0; wIdx < size; ++wIdx) {
			if ((i = send(_socket, message + wIdx, 1, 0)) == SOCKET_ERROR) return false;
			else if (i == 0) --wIdx;
		}
		commTime = time(nullptr);
		return true;
	}
	bool NetClient::write(void* message, ulong_64b size) {
		if (firstMessage) {
			Packet p;
			p.message = (char*)message;
			p.size = size;
			outPacketBuf->push_back(p);
			return true;
		}
		if (!canWrite) return false;
		char* bMsg = new char[size+1];
		bMsg[0] = remotePUID;
		++remotePUID;
		memcpy(bMsg + 1, message, size);
		++size;
		char* msg = encrypted ? Crypto::full_auto_encrypt(bMsg, size, pK, &size) : (char*)bMsg;
		_write(msg, size);
		if (encrypted) delete[] msg;
		delete[] bMsg;
		return true;
	}
	bool NetClient::write(char* message) { return write(message, strlen(message)+1); } // Send together with the null-terminator
	bool NetClient::writeBufferedPackets() {
		for (size_t t = 0; t < outPacketBuf->size(); ++t) if (!write(outPacketBuf->at(t).message, outPacketBuf->at(t).size)) { delete outPacketBuf; return false; };
		delete outPacketBuf;
		return true;
	}
	Packet NetClient::read() {
		if (packets->size() != 0) {
			Packet p = packets->at(0);
			packets->erase(packets->begin(), packets->begin() + 1); // Delete first buffered packet
			return p;
		}
		throw new _exception(); // No packets available!
	}
	void NetClient::setEventHandler(std::function<void(NetClient*, Packet)> _ev) {
		evt = _ev;

		// Process unhandled packets
		if (evt != nullptr)
			for (size_t t = packets->size(); t > 0; --t) {
				Packet p = packets->at(t - 1);
				packets->pop_back();
				evt(this, p);
			}
	}
	bool NetClient::isEncrypted() { return encrypted; }
	void NetClient::update() {
		int iResult = 0, rdErr;
		unsigned long rCount;
		rdErr = ioctlsocket(_socket, FIONREAD, &rCount);
		if (rdErr == SOCKET_ERROR) throw new _exception(); // Error using socket :(
		if ((builder==nullptr && (rCount >= 4)) || ((builder != nullptr) && (rCount > 0))) {
			iResult = recv(_socket, rBuf, BUFSIZE, 0);
			int offset = 0;

			// TODO: Implement properly
			if (builder == nullptr) {
				builder = new NetPacketBuilder(0);
				expect = *(ulong_64b*)rBuf;
				offset = 4;
			}
			if (iResult > 0)
				for (int i = offset; i < iResult; ++i)
					if (sparse->size() < BUF_2_MAX)
						sparse->push_back(rBuf[i]); // Drop anything over the absolute max
			commTime = time(nullptr);
			if(!firstMessage) flushPrecedingPings(sparse);
		}
		while (!firstMessage && hasFullMessage(sparse)) {
			Packet p;

			char* size = readSparse(sparse, sizeof(ulong_64b));
			memcpy(&p.size, size, sizeof(ulong_64b));
			delete[] size;

			p.message = readSparse(sparse, p.size);
			if (encrypted) p.message = Crypto::full_auto_decrypt(p.message, keys.privKey, &p.size);

			p.packetUID = p.message[0];
			if (p.packetUID != expectedNextPUID) continue; // Detect packet replay/mismatch
			else ++expectedNextPUID;

			--p.size;

			char* c = new char[p.size];
			memcpy(c, p.message + 1, p.size);
			delete[] p.message;
			p.message = c;

			if (evt == nullptr) packets->push_back(p);
			else evt(this, p); // Notify event handler of a new packet
		}
		if (iResult > 0) {
			if (firstMessage) {
				if (!fm_neg_hasLevel && sparse->size() >= 1) {
					fm_neg_hasLevel = true;
					char* readCrypt = readSparse(sparse, 1);
					CryptoLevel lvl = static_cast<CryptoLevel>(*readCrypt);
					free(readCrypt);
					if (cryptoLevelsAreCompatible(lvl, preferEncrypted)) {
						// Determine whether or not to use encryption
						encrypted = (preferEncrypted == CryptoLevel::Force) || (lvl == CryptoLevel::Force) || ((preferEncrypted == CryptoLevel::Prefer) && (lvl == CryptoLevel::Prefer));

						if (!encrypted) {
							firstMessage = false; // We're done here. No need to try to get a public key for an unencrypted channel
							writeBufferedPackets();
						}
						else {
							ulong_64b size;
							char* c = Crypto::RSA::serializeKey(keys.publKey, &size);
							_write(c, size); // This shouldn't be encrypted
							delete[] c;
						}
					}
					else throw new _exception(); // Incompatible cryptographic requirements!
				}
				if (fm_neg_hasLevel && !fm_neg_hasSize && encrypted && sparse->size() >= sizeof(ulong_64b)) {
					fm_neg_hasSize = true;
					char* readSize = readSparse(sparse, sizeof(ulong_64b));

					fm_neg_size = 0;
					memcpy(&fm_neg_size, readSize, sizeof(ulong_64b));
					free(readSize);
				}
				if (fm_neg_hasSize && sparse->size() >= fm_neg_size) {
					char* msg = readSparse(sparse, fm_neg_size);

					CryptoPP::StringSource src((const byte*)msg, fm_neg_size, true);
					pK.Load(src);

					firstMessage = false;
					writeBufferedPackets();
				}
			}
		}
		else if (iResult < 0 && _open) {
			_open = false;
			close();
		}
		if ((time(nullptr) - commTime) > 1) if (!ping()) { _open = false; close(); }
	}
	bool NetClient::isOpen() { return _open; }

	void NetClient::setOnDestroy(std::function<void()> call) { onDestroy = call; }

	ulong_64b NetClient::available() { return packets->size(); }



	bool NetServer::close() {
		if (!_open) return false;
		_open = false;
		for (ulong_64b t = clients->size(); t > 0; --t) {
			NetClient* s = clients->at(t - 1);
			s->close();
			clients->pop_back();
			delete s;
		}
		return true;
	}

	NetServer::NetServer(char* port, std::function<bool(NetClient*)> f = nullptr, CryptoLevel pref = CryptoLevel::None) : pref(pref) {
		if (pref != CryptoLevel::None) keys = Crypto::RSA::rsa_gen_keys();
		_open = true;
		timeoutHandler = NULL;
		onDestroy = NULL;
		handlers = new std::vector <std::function<bool(NetClient*)>>();
		if (f != NULL) handlers->push_back(f);
		clients = new std::vector<NetClient*>();
		clientListener = std::thread([this, port]() {
			SOCKET _server;
			WSADATA wsaData;
			int iResult;

			struct addrinfo *result = NULL;
			struct addrinfo hints;

			// Initialize Winsock
			iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (iResult != 0) throw new _exception();


			ZeroMemory(&hints, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			hints.ai_flags = AI_PASSIVE;

			// Resolve the server address and port
			iResult = getaddrinfo(NULL, port, &hints, &result);
			if (iResult) {
				throw new _exception();
			}

			// Create a SOCKET for connecting to server
			_server = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
			if (_server == INVALID_SOCKET) {
				freeaddrinfo(result);
				throw new _exception();
			}

			// Setup the TCP listening socket
			iResult = bind(_server, result->ai_addr, (int)result->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				freeaddrinfo(result);
				closesocket(_server);
				throw new _exception();  // Can't be fucked to deal with errors
			}
			if (listen(_server, 20) == SOCKET_ERROR) { // 20 is the backlog amount, i.e. amount of connections Windows will accept if program is busy and can't accept atm.
				closesocket(_server);
				throw new _exception();
			}
			timeval t;
			t.tv_sec = 0;
			t.tv_usec = 5000;
			do {
				fd_set connecting;
				connecting.fd_count = 1;
				connecting.fd_array[0] = _server;
				int i = select(NULL, &connecting, NULL, NULL, &t); // Check for new clients
				if (i == SOCKET_ERROR) {
					throw new _exception();
				}
				if (connecting.fd_count > 0) { // This checks if any new clients are tryig to connect. If not, don't block to await one; just continue to update clients
					SOCKET client = accept(_server, NULL, NULL);
					if (client == INVALID_SOCKET) {
						closesocket(_server);
						if (_open) throw new _exception();
						else break;
					}
					NetClient* cli = new NetClient(client, true, keys, this->pref, false);
					clients->push_back(cli);
					for (ulong_64b t = 0; t < handlers->size(); ++t)
						if (handlers->at(t)(cli))
							break;

				}
				updateClients();
			} while (_open);
			closesocket(_server);
			close();
		});

	}

	NetServer::~NetServer() {
		if (_open) close();
		handlers->clear();
		delete handlers;
		clients->clear();
		delete clients;
		onDestroy();
	}

	void NetServer::addHandler(std::function<bool(NetClient*)> evtH) {
		handlers->push_back(evtH);
	}

	void NetServer::clearHandlers() {
		handlers->clear();
	}

	void NetServer::updateClients() {
		for (ulong_64b t = clients->size(); t > 0; --t) {
			NetClient* c = clients->at(t - 1);
			if (!c->isOpen() || (timeoutHandler != NULL && !timeoutHandler(c))) {
				clients->erase(clients->begin() + t - 1, clients->begin() + t);
				c->close();
			}
			else c->update();
		}
	}
	CryptoLevel NetServer::getCryptoPreference() { return pref; }

	bool NetServer::isOpen() { return _open; }

	void NetServer::setOnDestroy(std::function<void()> call) { onDestroy = call; }
}