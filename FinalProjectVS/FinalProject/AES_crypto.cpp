#define _CRT_SECURE_NO_WARNINGS

#include "AES_crypto.h"
#include "Base64.h"

AES_crypto::AES_crypto(string key)
{
	key = key.substr(0, 16);
	char * str = (char *)key.c_str();
	for (size_t i = 0; i < 16; i++)
	{
		_key[i] = static_cast<unsigned char>(str[i]);
	}
	
	memset(_iv, 0x01, CryptoPP::AES::BLOCKSIZE);
}

string AES_crypto::Encrypt(string plaintext)
{
	string ciphertext;

	/*AES::Encryption aesEncryption(_key);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, _iv);
	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1);
	stfEncryptor.MessageEnd();*/

	CBC_Mode<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(_key, 16, _iv);
	StringSource(plaintext, true,
		new StreamTransformationFilter(encryptor, new StringSink(ciphertext),
			StreamTransformationFilter::PKCS_PADDING));

	return base64_encode(ciphertext);	
}

string AES_crypto::Decrypt(string ciphertext)
{
	string decryptedtext;

	AES::Decryption aesDecryption((unsigned char *)_key, AES::DEFAULT_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, _iv);
	StreamTransformationFilter stfDecryptor(cbcDecryption, new StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
	stfDecryptor.MessageEnd();

	return decryptedtext;
}
