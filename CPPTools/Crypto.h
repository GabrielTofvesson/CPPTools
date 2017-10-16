#pragma once

#ifndef LOGINDATA_H
#define LOGINDATA_H

#include "ArchAbstract.h"

#include <aes.h>
#include <rsa.h>

typedef unsigned short AES_IV_16;
typedef unsigned short AES_KEY_16;
typedef unsigned int AES_IV_32;
typedef unsigned int AES_KEY_32;

#ifdef _AES_16_BIT
// 128 bit AES encryption

#define _AES_BYTE_SIZE 16

typedef AES_IV_16 AES_IV;
typedef AES_KEY_16 AES_KEY;

#else
// 256 bit AES encryption

#define _AES_BYTE_SIZE 32

typedef AES_IV_32 AES_IV;
typedef AES_KEY_32 AES_KEY;

#endif

namespace Crypto {
	namespace AES {
		struct Payload {
			ulong_64b size;             // Payload metadata
			ulong_64b keySize;          // Key metadata
			AES_IV iv;		            // Initialization vector
			char* ldPayload;            // Encrypted Data
			char* key;		            // Encrypted AES key
			char* serialize(ulong_64b*);// Serialize data to be sent over the wire :P
		};
		Payload deserializePayload(void*, ulong_64b*);
		char* aes_encrypt(void* message, ulong_64b size, ulong_64b* resultingSize, AES_KEY key, AES_IV iv);
		char* aes_decrypt(void* message, ulong_64b size, ulong_64b* resultSize, AES_KEY key, AES_IV iv);
		char* aes_auto_decrypt(Payload p, ulong_64b* resultingSize);
		Payload aes_auto_encrypt(void* message, ulong_64b size);
	}

	namespace RSA {
		struct KeyData {
			CryptoPP::RSA::PrivateKey *privKey;
			CryptoPP::RSA::PublicKey *publKey;
		};

		char* serializeKey(CryptoPP::RSA::PublicKey&, ulong_64b* rSize);

		KeyData* rsa_gen_keys();
		char* rsa_encrypt(void* message, ulong_64b size, CryptoPP::RSA::PublicKey& pubKey, ulong_64b* resultingSize);
		char* rsa_decrypt(void* message, ulong_64b size, CryptoPP::RSA::PrivateKey& privKey, ulong_64b* resultingSize);
	}

	char* full_auto_encrypt(void* message, ulong_64b mSize, CryptoPP::RSA::PublicKey&, ulong_64b* rSize);
	char* full_auto_decrypt(void* cryptMessage, CryptoPP::RSA::PrivateKey&, ulong_64b* rSize);
}


#endif