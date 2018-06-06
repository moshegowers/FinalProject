#pragma once
#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <cryptopp\modes.h>
#include <cryptopp\aes.h>
#include <cryptopp\filters.h>
#include <string>
using namespace CryptoPP;
using namespace std;

class AES_crypto {
private:
	byte _key[AES::MAX_KEYLENGTH];
	byte _iv[AES::BLOCKSIZE];
public:
	AES_crypto() {};
	AES_crypto(string key);
	string Encrypt(string plaintext);
	string Decrypt(string ciphertext);
};

#endif
