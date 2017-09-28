#include "Crypto.h"

#include <randpool.h>
#include <modes.h>
#include <iostream>



namespace Crypto {

	namespace AES {
		// -------- AES START --------

		// Parameters:
		// message: Message to encrypt
		// size: Length of message (probably strlen(message))
		// resultingSize: Secondary return value representing string length of returned char*
		// aes_key: Key to use for encryption
		// aes_it: Initialization vector to use for encryption
		char* aes_encrypt(void* msg, ulong_64b size, ulong_64b* resultingSize, AES_KEY aes_key, AES_IV aes_iv) {
			char* message = (char*)msg;
			byte key[_AES_BYTE_SIZE], iv[_AES_BYTE_SIZE];
			memset(key, aes_key, _AES_BYTE_SIZE);
			memset(iv, aes_iv, _AES_BYTE_SIZE);

			std::string ciphertext;

			CryptoPP::AES::Encryption aesEncryption(key, _AES_BYTE_SIZE);
			CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

			if (size > (size_t)size) throw _exception();

			CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
			stfEncryptor.Put((const unsigned char*)message, size + 1);
			stfEncryptor.MessageEnd();

			ulong_64b t = ciphertext.size();

			(*resultingSize) = t;

			char* cipher = (char*)malloc(t);
			memcpy(cipher, ciphertext.c_str(), t);

			return cipher;
		}

		char* aes_decrypt(void* msg, ulong_64b size, ulong_64b* resultSize, AES_KEY aes_key, AES_IV aes_iv) {
			char* message = (char*)msg;
			byte key[_AES_BYTE_SIZE], iv[_AES_BYTE_SIZE];
			memset(key, aes_key, _AES_BYTE_SIZE);
			memset(iv, aes_iv, _AES_BYTE_SIZE);

			std::string decryptedtext;

			CryptoPP::AES::Decryption aesDecryption(key, _AES_BYTE_SIZE);
			CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

			CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
			stfDecryptor.Put((const unsigned char*)message, size);
			stfDecryptor.MessageEnd();

			*resultSize = decryptedtext.size();

			char* c = (char*)malloc(*resultSize);
			//memset(c, 0, decryptedtext.size());
			memcpy(c, decryptedtext.c_str(), decryptedtext.size());

			decryptedtext.~basic_string();

			return c;
		}

		// Just use this :P
		Payload aes_auto_encrypt(void* msg, ulong_64b size) {
			char* message = (char*)msg;
			Payload p;
			srand(time(NULL));

			p.key = (char*)malloc(sizeof(AES_KEY));
			AES_KEY k = (AES_KEY)rand();

			p.keySize = sizeof(AES_KEY);

			memcpy(p.key, &k, sizeof(AES_KEY));
			p.iv = (AES_IV)rand();

			ulong_64b s;
			p.ldPayload = aes_encrypt(message, size, &s, *(AES_KEY*)p.key, p.iv);
			p.size = s;

			return p;
		}

		// This too :P
		char* aes_auto_decrypt(Payload p, ulong_64b* resultingSize) {
			return aes_decrypt(p.ldPayload, p.size, resultingSize, *(AES_KEY*)p.key, p.iv);
		}

		char* Payload::serialize(ulong_64b* size) {
			char* ser = (char*)new char[*size=((sizeof(ulong_64b) * 2) + sizeof(AES_IV) + this->size + this->keySize)];
			ulong_64b offset = 0;
			memcpy(ser + offset, &this->size, sizeof(ulong_64b));
			offset += sizeof(ulong_64b);
			memcpy(ser + offset, &this->keySize, sizeof(ulong_64b));
			offset += sizeof(ulong_64b);
			memcpy(ser + offset, &this->iv, sizeof(AES_IV));
			offset += sizeof(AES_IV);
			memcpy(ser + offset, this->ldPayload, this->size);
			offset += this->size;
			memcpy(ser + offset, this->key, this->keySize);
			return ser;
		}

		Payload deserializePayload(void* frm, ulong_64b* readBytes) {
			char* from = (char*)frm;
			Payload data;
			ulong_64b offset = 0;

			// Read target sizes
			memcpy(&data.size, from + offset, sizeof(ulong_64b));
			offset += sizeof(ulong_64b);
			memcpy(&data.keySize, from + offset, sizeof(ulong_64b));
			offset += sizeof(ulong_64b);
			memcpy(&data.iv, from + offset, sizeof(AES_IV));
			offset += sizeof(AES_IV);

			// Allocate target sizes
			data.ldPayload = (char*)malloc(data.size);
			data.key = (char*)malloc(data.keySize);

			// Read data
			memcpy(data.ldPayload, from + offset, data.size);
			offset += data.size;
			memcpy(data.key, from + offset, data.keySize);
			offset += data.keySize;

			*readBytes = offset;

			return data;
		}
		// -------- AES END --------
	}

	namespace RSA {
		// -------- RSA START --------
		KeyData rsa_gen_keys() {
			KeyData k;

			CryptoPP::InvertibleRSAFunction params;
			CryptoPP::RandomPool rng;

			time_t t = time(NULL);
			rng.IncorporateEntropy((const byte*)&t, sizeof(t) * 8);

			params.GenerateRandomWithKeySize(rng, 3072);
			k.privKey = CryptoPP::RSA::PrivateKey(params);
			k.publKey = CryptoPP::RSA::PublicKey(params);
			return k;
		}

		char* serializeKey(CryptoPP::RSA::PublicKey& func, ulong_64b* rSize) {
			CryptoPP::ByteQueue queue;
			func.Save(queue);
			//func.DEREncodePublicKey(queue);


			byte* shortened = (byte*)malloc(*rSize=queue.TotalBytesRetrievable());
			memset(shortened, 0, *rSize);

			std::vector<byte> spk;
			spk.resize(queue.TotalBytesRetrievable());

			CryptoPP::ArraySink snk(&spk[0], spk.size());
			queue.CopyTo(snk);

			for (ulong_64b t = 0; t < spk.size(); ++t) shortened[t] = spk.at(t);

			return (char*)shortened;
		}

		char* rsa_encrypt(void* msg, ulong_64b size, CryptoPP::RSA::PublicKey& pubKey, ulong_64b* resultingSize) {
			char* message = (char*)msg;
			CryptoPP::RandomPool rng;

			time_t t = time(NULL);
			rng.IncorporateEntropy((const byte*)&t, sizeof(t) * 8);

			CryptoPP::RSAES_OAEP_SHA_Encryptor e(pubKey);
			std::string cipher;
			CryptoPP::StringSource s((const byte*)message, size, true, new CryptoPP::PK_EncryptorFilter(rng, e, new CryptoPP::StringSink(cipher)));

			*resultingSize = cipher.size();

			char* c = (char*)malloc(cipher.size());
			memset(c, 0, cipher.size());
			memcpy(c, cipher.c_str(), cipher.size());
			return c;
		}

		char* rsa_decrypt(void* msg, ulong_64b size, CryptoPP::RSA::PrivateKey& privKey, ulong_64b* resultingSize) {
			char* message = (char*)msg;
			CryptoPP::RandomPool rng;

			time_t t = time(NULL);
			rng.IncorporateEntropy((const byte*)&t, sizeof(t) * 8);

			CryptoPP::RSAES_OAEP_SHA_Decryptor e(privKey);
			std::string clear;
			CryptoPP::StringSource s((const byte*)message, size, true, new CryptoPP::PK_DecryptorFilter(rng, e, new CryptoPP::StringSink(clear)));

			*resultingSize = clear.size();

			char* c = (char*)malloc(clear.size());
			memset(c, 0, clear.size());
			memcpy(c, clear.c_str(), clear.size());
			return c;
		}
		// -------- RSA END --------
	}

	char* full_auto_encrypt(void* msg, ulong_64b mSize, CryptoPP::RSA::PublicKey& pk, ulong_64b* rSize) {
		AES::Payload p = AES::aes_auto_encrypt(msg, mSize);
		p.key = RSA::rsa_encrypt(p.key, p.keySize, pk, &p.keySize);
		return p.serialize(rSize);
	}

	char* full_auto_decrypt(void* msg, CryptoPP::RSA::PrivateKey& pk, ulong_64b* rSize) {
		ulong_64b size;
		AES::Payload p = AES::deserializePayload(msg, &size);
		p.key = RSA::rsa_decrypt(p.key, p.keySize, pk, &p.keySize);
		return AES::aes_auto_decrypt(p, rSize);
	}
}