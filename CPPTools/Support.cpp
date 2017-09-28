#include <iostream>
#include <memory>

#include "Support.h"

namespace Tools {
	char* strappend(char* to, char* from) {
		ulong_64b l, l1;
		to = (char*)realloc(to, (l = strlen(to)) + (l1 = strlen(from))+1);
		memcpy(to + l, from, l1);
		to[l + l1] = 0;
		return to;
	}

	char* strappend(char* to, const char* from) {
		ulong_64b l, l1;
		to = (char*)realloc(to, (l = strlen(to)) + (l1 = strlen(from))+1);
		memcpy(to + l, from, l1);
		to[l + l1] = 0;
		return to;
	}

	char* strappend(const char* from, char* to) {
		ulong_64b l, l1;
		to = (char*)realloc(to, (l = strlen(to)) + (l1 = strlen(from))+1);
		memcpy(to + l1, to, l);
		memcpy(to, from, l1);
		to[l + l1] = 0;
		return to;
	}

	char* __cdecl strappend(const char* from, const char* from1) {
		ulong_64b l, l1;
		char* to = (char*)malloc((l = strlen(from)) + (l1 = strlen(from1))+1);
		memcpy(to, from, l);
		memcpy(to + l, from1, l1);
		to[l + l1] = 0;
		return to;
	}

	void destructivePrint(char* message, ulong_64b size) {
		for (ulong_64b t = 0; t < size; ++t) std::cout << message[t];
		free(message);
	}

	void destructivePrint(char* message) {
		std::cout << message;
		free(message);
	}

	void destructivePrintln(char* message, ulong_64b size) {
		destructivePrint(message, size);
		std::cout << std::endl;
	}

	void destructivePrintln(char* message) {
		destructivePrint(message);
		std::cout << std::endl;
	}

	ulong_64b indexOf(char* in, char find) {
		ulong_64b t = strlen(in);
		for (ulong_64b t1 = 0; t1 < t; ++t1) if (in[t1] == find) return t1;
		return -1;
	}

	ulong_64b lastIndexOf(char* in, char find) {
		ulong_64b t = strlen(in);
		for (ulong_64b t1 = 0; t1 < t; ++t1) if (in[t - t1 - 1] == find) return t - t1;
		return -1;
	}

	char* copydata(const char* from, ulong_64b readBytes) {
		char* c = (char*)malloc(readBytes);
		memcpy(c, from, readBytes);
		return c;
	}

	char* toHexString(const void* data, ulong_64b size) {
		char* c = (char*)data;

		ulong_64b lastNonZero = 0;
		for (ulong_64b t = 0; t < size; ++t) if (c[t] != 0) lastNonZero = t;
		if (lastNonZero == 0) return (char*)memset(malloc(1), '0', 1);

		char* c1 = (char*)malloc(lastNonZero * 2);
		for (ulong_64b t = 0; t < lastNonZero; ++t) {
			c1[2 * t] = (c[t]) & 15;
			if (c1[(2 * t)] < 9) c1[(2 * t)] += 48;
			else c1[(2 * t)] += 55;

			c1[(2 * t) + 1] = (c[t] >> 4) & 15;
			if (c1[(2 * t) + 1] < 9) c1[(2 * t) + 1] += 48;
			else c1[(2 * t) + 1] += 55;
		}
		return c1;
	}

	char* toHexString(ulong_64b value) { return toHexString(&value, sizeof(value)); }

	bool isDigit(char c) { return (c > 47) && (c < 58); }

	bool isIP(char* c) {
		size_t t = strlen(c);
		size_t count = 0;
		for (size_t t1 = 0; t1 < t; ++t1) {
			if (c[t1] == '.') {
				if ((t1 + 1) == t) return false;
				++count;
			}
			else if (!isDigit(c[t1])) return false;
			if (count > 3) return false;
		}
		return count == 3;
	}

	bool isNumber(char* c) {
		for (size_t t = strlen(c); t > 0; --t) if (!isDigit(c[t - 1])) return false;
		return true;
	}
}

namespace IO {

	bool cryptoLevelsAreCompatible(CryptoLevel l1, CryptoLevel l2) {
		return !(((l1 == CryptoLevel::None) && (l2 == CryptoLevel::Force)) || ((l2 == CryptoLevel::None) && (l1 == CryptoLevel::Force)));
	}

	char* __cdecl readSparse(std::vector<char>* sparse, ulong_64b rSize, bool pop = true) {
		if (sparse->size() < rSize) throw new _exception(); // This should never happen if function is used correctly
		char* c = new char[rSize];
		for (ulong_64b b = 0; b < rSize; ++b) c[b] = sparse->at(b);
		if(pop) sparse->erase(sparse->begin(), sparse->begin() + rSize);
		return c;
	}

	bool hasFullMessage(std::vector<char> *sparse) {
		if (sparse->size() < sizeof(ulong_64b)) return false;
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
		if(send(_socket, &cryptoPref, 1, 0)==SOCKET_ERROR) throw new _exception(); // Cannot establish connection :(
		//_write(&cryptoPref, 1);
		if (!noThread) listener = std::thread([this]() { while(_open) { update(); Sleep(25); } }); // Setup separate thread for reading new data
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
		result &= (SOCKET_ERROR==shutdown(_socket, SD_BOTH));
		closesocket(_socket);
		return result;
	}
	void NetClient::closeWrite() {
		shutdown(_socket, SD_SEND);
		canWrite = false;
	}
	bool NetClient::_write(char* message, ulong_64b size) {
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
		char* msg = encrypted?Crypto::full_auto_encrypt(message, size, pK, &size):(char*)message;
		_write(msg, size);
		if (encrypted) delete[] msg;
		return true;
	}
	bool NetClient::write(char* message) { return write(message, strlen(message)); }
	bool NetClient::writeBufferedPackets() {
		for (size_t t = 0; t < outPacketBuf->size(); ++t) if (!write(outPacketBuf->at(t).message, outPacketBuf->at(t).size)) { delete outPacketBuf; return false; };
		delete outPacketBuf;
		return true;
	}
	Packet NetClient::read() {
		if (packets->size() != 0) {
			Packet p = packets->at(0);
			packets->erase(packets->begin(), packets->begin()+1); // Delete first buffered packet
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
		int iResult = 0;
		unsigned long rCount;
		int rdErr = ioctlsocket(_socket, FIONREAD, &rCount);
		if (rdErr == SOCKET_ERROR) throw new _exception(); // Error using socket :(
		if (rCount > 0) {
			iResult = recv(_socket, rBuf, BUFSIZE, 0);
			if (iResult > 0)
				for (int i = 0; i < iResult; ++i)
					if (sparse->size() < BUF_2_MAX)
						sparse->push_back(rBuf[i]); // Drop anything over the absolute max
		}
		while (!firstMessage && hasFullMessage(sparse)) {
			Packet p;
			char* size = readSparse(sparse, sizeof(ulong_64b));
			memcpy(&p.size, size, sizeof(ulong_64b));
			delete[] size;
			p.message = readSparse(sparse, p.size);
			if (encrypted) p.message = Crypto::full_auto_decrypt(p.message, keys.privKey, &p.size);
			if(evt==nullptr) packets->push_back(p);
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
		}else if (iResult < 0 && _open) {
			_open = false;
			close();
		}
	}
	bool NetClient::isOpen() { return _open; }

	void NetClient::setOnDestroy(std::function<void()> call) { onDestroy = call; }

	ulong_64b NetClient::available() { return packets->size(); }



	bool NetServer::close() {
		if (!_open) return false;
		_open = false;
		for (ulong_64b t = clients->size(); t > 0; --t) {
			NetClient* s = clients->at(t-1);
			s->close();
			clients->pop_back();
			delete s;
		}
		return true;
	}

	NetServer::NetServer(char* port, std::function<bool(NetClient*)> f=nullptr, CryptoLevel pref=CryptoLevel::None) : pref(pref) {
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
			NetClient* c = clients->at(t-1);
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