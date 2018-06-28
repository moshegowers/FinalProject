#pragma once

#ifndef DH_H
#define DH_H
#include <cryptopp\cryptlib.h>
#include <cryptopp\dh.h>
#include <cryptopp\dh2.h>
#include <cryptopp\osrng.h>
#include <cryptopp\integer.h>
#include <cryptopp\nbtheory.h>
#include <iostream>
using namespace CryptoPP;
using namespace std;


class DiffieHelman {
private:

	DH _dh = DH();
	Integer _p;
	Integer _g;
	SecByteBlock _privateKey;
	SecByteBlock _publicKey;
public:
	DiffieHelman();
	string get_p();
	int get_g();
	string get_public_key();
	string set_sheard_key(const char *pubKey);
};

#endif
