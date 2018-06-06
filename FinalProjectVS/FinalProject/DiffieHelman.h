#pragma once

#ifndef DH_H
#define DH_H
#include <cryptopp\cryptlib.h>
#include <cryptopp\dh.h>
#include <cryptopp\dh2.h>
#include <cryptopp\osrng.h>
#include <cryptopp\integer.h>
#include <cryptopp\nbtheory.h>
//#include <cryptopp\filters.h>
//#include <cryptopp\eccrypto.h>
//#include <cryptopp\argnames.h>
//#include <cryptopp\smartptr.h>
//#include <cryptopp\oids.h>
//#include <cryptopp\asn.h>
//#include <cryptopp\hex.h>
//#include <cryptopp\ec2n.h>
//#include <cryptopp\misc.h>
//#include <cryptopp\ecp.h>
#include <iostream>
using namespace CryptoPP;
using namespace std;

//#include <CkDh.h>
//#include <CkCrypt2.h>

class DiffieHelman {
private:
	//CkDh _dh
	DH _dh = DH();
	Integer _p;
	Integer _g;
	SecByteBlock _privateKey;
	SecByteBlock _publicKey;
public:
	DiffieHelman();
	string get_p();
	int get_g();
	void set_pg(const char *p, int g);
	string get_public_key();
	string set_sheard_key(const char *pubKey);
};

#endif
