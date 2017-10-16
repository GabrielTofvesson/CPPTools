#include "Net.h"
#include "Support.h"

#include <future>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>


namespace IO {

	AsyncKeys::AsyncKeys() {
		gen = std::async(std::launch::async, [this]() {
			Crypto::RSA::KeyData *data = Crypto::RSA::rsa_gen_keys();
			done = true;
			return data;
		});
		done = suppressDelete = false;
	}
	AsyncKeys::AsyncKeys(Crypto::RSA::KeyData* predef) {
		done = suppressDelete = true;
		keys = predef;
	}
	AsyncKeys::~AsyncKeys() {
		if (!suppressDelete) {
			delete keys->privKey;
			delete keys->publKey;
			delete keys;
		}
	}
	Crypto::RSA::KeyData* AsyncKeys::get() {
		if (!done) {
			keys = gen.get();
		}
		return keys;
	}


	bool cryptoLevelsAreCompatible(CryptoLevel l1, CryptoLevel l2) {
		return !(((l1 == CryptoLevel::None) && (l2 == CryptoLevel::Force)) || ((l2 == CryptoLevel::None) && (l1 == CryptoLevel::Force)));
	}

	char* __cdecl readSparse(std::vector<char>* sparse, ulong_64b rSize, bool pop = true) {
		if (sparse->size() < rSize) throw new std::exception(); // This should never happen if function is used correctly
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



	void NetClient::sharedSetup(bool setupKeys) {
		if (setupKeys && (preferEncrypted != CryptoLevel::None)) keyData = new AsyncKeys();
		packets = new std::vector<Packet>();
		sparse = new std::vector<char>();
		outPacketBuf = new std::vector<Packet>();
		rBuf.resize(1);
		_open = true;
		canWrite = true;
		evt = nullptr;
		char cryptoPref = static_cast<char>(preferEncrypted);
		commTime = time(nullptr);
		if (send(_socket, &cryptoPref, 1, 0) == SOCKET_ERROR) throw new std::exception(); // Cannot establish connection :(
		if (!noThread) listener = std::thread([](NetClient& cli) { while (cli._open) { cli.update(); Sleep(25); } }, std::ref(*this)); // Setup separate thread for reading new data
	}
	NetClient::NetClient(char* ipAddr, char* port, CryptoLevel preferEncrypted) : NetClient(ipAddr, port, preferEncrypted, true) {}
	NetClient::NetClient(char* ipAddr, char* port, CryptoLevel preferEncrypted, bool setupKeys) :
		preferEncrypted(preferEncrypted), startNegotiate(false)
	{
		_socket = INVALID_SOCKET;
		this->noThread = false;

		WSADATA wsaData;
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) throw new std::exception();


		struct addrinfo *result = NULL, *ptr = NULL, hints;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		iResult = getaddrinfo(ipAddr, port, &hints, &result);

		if (iResult) throw new std::exception();

		for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

			// Create a SOCKET for connecting to server
			_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
			if (_socket == INVALID_SOCKET) {
				throw new std::exception();
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

		if (_socket == INVALID_SOCKET) throw new std::exception();

		sharedSetup(setupKeys);
	}

	NetClient::NetClient(char* ipAddr, char* port, AsyncKeys *keyData, CryptoLevel level) : NetClient(ipAddr, port, level, false) { this->keyData = keyData; }

	NetClient::NetClient(SOCKET wrap, bool noThread, AsyncKeys &keyData, CryptoLevel preferEncrypted, bool startNegotiate) :
		preferEncrypted(preferEncrypted), startNegotiate(startNegotiate)
	{
		_socket = wrap;
		this->noThread = noThread;
		this->keyData = new AsyncKeys(keyData.get());
		sharedSetup(false);
	}

	NetClient::~NetClient() {
		delete keyData;
		for (std::pair<char*, std::pair<ulong_64b, char*>*> *p : associatedData) {
			delete[] p->first;
			delete[] p->second->second;
			delete p->second;
			delete p;
		}
		associatedData.clear();
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
		delete[] c;
		return true;
	}

	size_t NetClient::getBOPCount() { return firstMessage ? outPacketBuf->size() : 0; }

	bool NetClient::_write(char* message, ulong_64b size) {
		if (size==FLAG_PING) throw new std::exception();	   // Max value is reserved for ping packet
		int i;
		char* c = new char[sizeof(ulong_64b)];
		memcpy(c, &size, sizeof(ulong_64b));
		for (ulong_64b wIdx = 0; wIdx < sizeof(ulong_64b); ++wIdx) {
			if ((i = send(_socket, c + wIdx, 1, 0)) == SOCKET_ERROR) {
				delete[] message;
				delete[] c;
				return false;
			}
			else if (i == 0) --wIdx;
		}
		for (ulong_64b wIdx = 0; wIdx < size; ++wIdx) {
			if ((i = send(_socket, message + wIdx, 1, 0)) == SOCKET_ERROR) {
				delete[] message;
				delete[] c;
				return false;
			}
			else if (i == 0) --wIdx;
		}
		commTime = time(nullptr);
		if(autoDelete) delete[] message;
		delete[] c;
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
		throw new std::exception(); // No packets available!
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
		if (rCount > 0) {
			rBuf.resize(rCount);
			iResult = recv(_socket, &rBuf[0], rCount, 0);
			if (iResult > 0)
				for (int i = 0; i < iResult; ++i)
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
			if (encrypted) p.message = Crypto::full_auto_decrypt(p.message, *keyData->get()->privKey, &p.size);

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
							char* c = Crypto::RSA::serializeKey(*keyData->get()->publKey, &size);
							_write(c, size); // This shouldn't be encrypted
							delete[] c;
						}
					}
					else throw new std::exception(); // Incompatible cryptographic requirements!
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
		if (autoPing && ((time(nullptr) - commTime) > 1)) if (!ping()) { _open = false; close(); }
	}
	bool NetClient::isOpen() { return _open; }

	void NetClient::setOnDestroy(std::function<void()> call) { onDestroy = call; }


	std::pair<ulong_64b, char*> NetClient::getValue(const char* name, bool copy) {
		for(std::pair<char*, std::pair<ulong_64b, char*>*>* p : associatedData)
			if (!strcmp(p->first, name)) {
				char* c = copy ? new char[p->second->first] : p->second->second;
				if (copy) memcpy(c, p->second->second, p->second->first);
				return std::pair<ulong_64b, char*>(p->second->first, c);
			}
		return std::pair<ulong_64b, char*>(0, nullptr);
	}
	char* NetClient::getStrValue(const char* name, bool copy) {
		return getValue(name, copy).second;
	}
	void NetClient::setValue(const char* name, std::pair<ulong_64b, char*> value, bool copy, bool del) {
		for (std::pair<char*, std::pair<ulong_64b, char*>*>* p : associatedData)
			if (!strcmp(p->first, name)) {
				p->second->first = value.first;
				if (del) delete[] p->second->second;
				char* c = copy ? new char[value.first] : value.second;
				if (copy) memcpy(c, value.second, value.first);
				p->second->second = c;
				return;
			}
		std::pair<char*, std::pair<ulong_64b, char*>*>* p = new std::pair<char*, std::pair<ulong_64b, char*>*>();
		p->first = (char*)name;
		p->second = new std::pair<ulong_64b, char*>();
		p->second->first = value.first;
		if (del) delete[] p->second->second;
		char* c = copy ? new char[value.first] : value.second;
		if (copy) memcpy(c, value.second, value.first);
		p->second->second = c;

		associatedData.push_back(p);
	}
	void NetClient::setValue(const char* name, char* value, bool copy, bool del) {
		setValue(name, std::pair<ulong_64b, char*>(strlen(value), value), copy, del);
	}
	bool NetClient::removeValue(const char* name, bool del) {
		for (size_t t = associatedData.size(); t>0; --t)
			if (!strcmp(associatedData.at(t-1)->first, name)) {
				if (del) delete[] associatedData.at(t-1)->second->second;
				associatedData.erase(associatedData.begin()+t-1, associatedData.begin()+t);
				return true;
			}
		return false;
	}
	bool NetClient::containsKey(const char* name) {
		for (size_t t = associatedData.size(); t>0; --t)
			if (!strcmp(associatedData.at(t - 1)->first, name))
				return true;
		return false;
	}

	ulong_64b NetClient::available() { return packets->size(); }





	void NetServer::sharedSetup(char* port, std::function<bool(NetClient*)> f) {
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
			if (iResult != 0) throw new std::exception();


			ZeroMemory(&hints, sizeof(hints));
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			hints.ai_flags = AI_PASSIVE;

			// Resolve the server address and port
			iResult = getaddrinfo(NULL, port, &hints, &result);
			if (iResult) {
				throw new std::exception();
			}

			// Create a SOCKET for connecting to server
			_server = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
			if (_server == INVALID_SOCKET) {
				freeaddrinfo(result);
				throw new std::exception();
			}

			// Setup the TCP listening socket
			iResult = bind(_server, result->ai_addr, (int)result->ai_addrlen);
			if (iResult == SOCKET_ERROR) {
				freeaddrinfo(result);
				closesocket(_server);
				throw new std::exception();  // Can't be fucked to deal with errors
			}
			if (listen(_server, 20) == SOCKET_ERROR) { // 20 is the backlog amount, i.e. amount of connections Windows will accept if program is busy and can't accept atm.
				closesocket(_server);
				throw new std::exception();
			}
			timeval t;
			t.tv_sec = 0;
			t.tv_usec = 5000;
			do {
				fd_set connecting;
				connecting.fd_count = 1;
				connecting.fd_array[0] = _server;
				int i = select(NULL, &connecting, NULL, NULL, &t); // Check for new clients
				if (i == SOCKET_ERROR) throw new std::exception();
				if (connecting.fd_count > 0) { // This checks if any new clients are tryig to connect. If not, don't block to await one; just continue to update clients
					SOCKET client = accept(_server, NULL, NULL);
					if (client == INVALID_SOCKET) {
						closesocket(_server);
						if (_open) throw new std::exception();
						else break;
					}
					NetClient* cli = new NetClient(client, true, *keyData, this->pref, false);
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

	NetServer::NetServer(char* port, std::function<bool(NetClient*)> f, CryptoLevel pref) : pref(pref) {
		if (pref != CryptoLevel::None) keyData = new AsyncKeys();
		sharedSetup(port, f);
	}


	NetServer::NetServer(char* port, std::function<bool(NetClient*)> f, AsyncKeys &keyData, CryptoLevel level) : pref(level) {
		this->keyData = new AsyncKeys(keyData.get());
		sharedSetup(port, f);
	}

	NetServer::~NetServer() {
		delete keyData;
		if (_open) close();
		handlers->clear();
		delete handlers;
		for (NetClient *cli : *clients) delete cli;
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

	void NetServer::setAutoPing(bool b) { for (NetClient* cli : *clients) cli->autoPing = b; }



	void writeState(NetClient& cli, const char* stateName, char state) {
		char* c = cli.getStrValue(stateName, false);
		if (c == nullptr) c = new char[0];
		c[0] = state;
		cli.setValue(stateName, c, false, false); // Write/overwrite
	}

	char readState(NetClient& cli, const char* stateName) {
		char* c = cli.getStrValue(stateName, false);
		if (c == nullptr) return 0;
		else return *c;
	}

	PartialNetworkStream::PartialNetworkStream(NetClient& client, bool noBuffer, bool permissive) :
		std::ostream(std::_Uninitialized::_Noinit),
		client(client),
		buffer(noBuffer?nullptr:new std::vector<char>()),
		permissive(permissive)
	{ /* NOP */}

	PartialNetworkStream::~PartialNetworkStream() {
		if (client.isOpen() && !stateIs(client, PartialCommState::COMM_FULL)) {
			sendState(PartialCommState::COMM_FULL);
			writeState(client, STREAM_ATTRIB, PartialCommState::COMM_FULL);
		}
		client.removeValue(STREAM_ATTRIB); // Cleanup
	}
	void PartialNetworkStream::write(char* message, std::streamsize size, bool autoFlush) {
		bool isPartial = stateIs(client, PartialCommState::COMM_PARTIAL);
		if (!isPartial || autoFlush || (size > STREAM_BUFMIN)) {
			if(isPartial) flush();
			client.write(message, size);
		}
		else {
			for (std::streamsize t = 0; t < size; ++t) buffer->push_back(message[t]);
			if (buffer->size() > STREAM_BUFMIN) flush();
		}
	}
	void PartialNetworkStream::writeNonPartial(char* message, std::streamsize size) {
		bool b = stateIs(client, PartialCommState::COMM_PARTIAL);
		if (b) client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));
		client.write(message, size);
		if (b) client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));
	}
	void PartialNetworkStream::flush() {
		if(!check(PartialCommState::COMM_FULL)) return; // Check failed in a permissive state
		if (buffer->size() == 0) return;
		bool b = stateIs(client, PartialCommState::COMM_PAUSE);
		if (b) client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE)); // Temporarily set the remote read state to PARTIAL
		client.write(&buffer->at(0), buffer->size());
		if (b) client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));   // Set the remote read state back to PAUSE
		buffer->clear();
	}
	bool PartialNetworkStream::check(PartialCommState state) {
		if (readState(client, STREAM_ATTRIB) == state) {
			if (permissive) return false;
			throw new std::exception("Stream is not open!");
		}
		return true;
	}
	void PartialNetworkStream::sendState(PartialCommState state) {
		switch (getCommState()) {
		case PartialCommState::COMM_PAUSE:
			if (state == PartialCommState::COMM_FULL) {
				client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));
				client.write((char*)&STREAM_DELIMIT, sizeof(STREAM_DELIMIT));
			}
			else if (state == PartialCommState::COMM_PARTIAL) client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));
			break;
		case PartialCommState::COMM_PARTIAL:
			if (state == PartialCommState::COMM_FULL) client.write((char*)&STREAM_DELIMIT, sizeof(STREAM_DELIMIT));
			else if (state == PartialCommState::COMM_PAUSE) client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));
			break;
		case PartialCommState::COMM_FULL:
			if (state == PartialCommState::COMM_PARTIAL) client.write((char*)&STREAM_DELIMIT, sizeof(STREAM_DELIMIT));
			else if (state == PartialCommState::COMM_PAUSE) {
				client.write((char*)&STREAM_DELIMIT, sizeof(STREAM_PAUSE));
				client.write((char*)&STREAM_PAUSE, sizeof(STREAM_PAUSE));
			}
			break;
		}
	}

	void PartialNetworkStream::endPartial() {
		flush();
		sendState(PartialCommState::COMM_FULL);
		writeState(client, STREAM_ATTRIB, PartialCommState::COMM_FULL);
	}
	void PartialNetworkStream::startPartial() {
		sendState(PartialCommState::COMM_PARTIAL);
		writeState(client, STREAM_ATTRIB, PartialCommState::COMM_PARTIAL);
	}
	PartialCommState PartialNetworkStream::getCommState() {
		return static_cast<PartialCommState>(readState(client, STREAM_ATTRIB));
	}
	bool PartialNetworkStream::stateIs(NetClient& cli, PartialCommState state) { return readState(cli, STREAM_ATTRIB) == state; }
	PartialDataState PartialNetworkStream::accept(NetClient& cli, Packet& pkt) {
		bool toggle_partial = (pkt.size-1) == sizeof(STREAM_DELIMIT) && ((*(ulong_64b*)pkt.message) == STREAM_DELIMIT);
		bool toggle_pause = !toggle_partial && ((pkt.size-1) == sizeof(STREAM_PAUSE) && ((*(ulong_64b*)pkt.message) == STREAM_PAUSE));
		if (!toggle_partial && !toggle_pause) return PartialDataState::DATA;
		else if (toggle_partial) {
			if (stateIs(cli, PartialCommState::COMM_FULL)) {
				writeState(cli, STREAM_ATTRIB, PartialCommState::COMM_PARTIAL);
				return PartialDataState::START;
			}
			else if (stateIs(cli, PartialCommState::COMM_PAUSE)) {
				writeState(cli, STREAM_ATTRIB, PartialCommState::COMM_PARTIAL);
				return PartialDataState::RESUME;
			}
			else {
				writeState(cli, STREAM_ATTRIB, PartialCommState::COMM_FULL);
				return PartialDataState::END;
			}
		}
		else /* if(toggle_pause) */{
			if (stateIs(cli, PartialCommState::COMM_FULL)) {
				writeState(cli, STREAM_ATTRIB, PartialCommState::COMM_PAUSE);
				return PartialDataState::PAUSE;
			}
			else if (stateIs(cli, PartialCommState::COMM_PAUSE)) {
				writeState(cli, STREAM_ATTRIB, PartialCommState::COMM_PARTIAL);
				return PartialDataState::RESUME;
			}
			else {
				writeState(cli, STREAM_ATTRIB, PartialCommState::COMM_PAUSE);
				return PartialDataState::PAUSE;
			}
		}
	}
}