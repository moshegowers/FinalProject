#define _CRT_SECURE_NO_WARNINGS

#include "AES_crypto.h"
#include "Base64.h"

AES_crypto::AES_crypto(string key)
{
	key = key.substr(0, 32);
	char * str = (char *)key.c_str();
	for (size_t i = 0; i < 32; i++)
	{
		_key[i] = static_cast<unsigned char>(str[i]);
	}
	
	memset(_iv, 0x31, CryptoPP::AES::BLOCKSIZE);
}

string AES_crypto::Encrypt(string plaintext)
{
	string ciphertext;

	/*size_t pad = 16 - (plaintext.length() % 16);
	for (size_t i = 0; i < pad; i++)
	{
		plaintext.push_back((char)pad);
	}
	AES::Encryption aesEncryption(_key);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, _iv);
	StreamTransformationFilter stfEncryptor(cbcEncryption, new StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1);
	stfEncryptor.MessageEnd();*/

	CBC_Mode<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(_key, 32, _iv);
	StringSource(plaintext, true,
		new StreamTransformationFilter(encryptor, new StringSink(ciphertext),
			StreamTransformationFilter::PKCS_PADDING));
	
	//return ciphertext;

	return base64_encode(ciphertext);	
}

string AES_crypto::Decrypt(string ciphertext)
{
	ciphertext = base64_decode(ciphertext);
	string decryptedtext;

	CBC_Mode<AES>::Decryption decryptor;
	decryptor.SetKeyWithIV(_key, 32, _iv);


	StringSource(ciphertext, true,
		new StreamTransformationFilter(decryptor, new StringSink(decryptedtext),
			StreamTransformationFilter::PKCS_PADDING));

	return decryptedtext;
}
