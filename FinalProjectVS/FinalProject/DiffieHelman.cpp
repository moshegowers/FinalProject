#include "DiffieHelman.h"

DiffieHelman::DiffieHelman()
{
	AutoSeededRandomPool rnd;
	PrimeAndGenerator pg;
	pg.Generate(1, rnd, 512, 511);
	_p = pg.Prime();
	Integer q = pg.SubPrime();
	_g = pg.Generator();
	_dh = DH(_p, q, _g);

	_privateKey = SecByteBlock(_dh.PrivateKeyLength());
	_publicKey = SecByteBlock(_dh.PublicKeyLength());
	_dh.GenerateKeyPair(rnd, _privateKey, _publicKey);
}

string DiffieHelman::get_p()
{
	stringstream ss;
	ss << _p;
	return ss.str();
}

int DiffieHelman::get_g()
{
	stringstream ss;
	ss << _g;
	return stoi(ss.str());
}

string DiffieHelman::get_public_key()
{
	Integer pub;
	pub.Decode(_publicKey.BytePtr(), _publicKey.SizeInBytes());
	stringstream ss;
	ss << pub;
	return ss.str();
}

string DiffieHelman::set_sheard_key(const char *pubKey)
{
	Integer i(pubKey), pk, sk;
	pk.Decode(_privateKey.BytePtr(), _privateKey.SizeInBytes());
	sk = a_exp_b_mod_c(i, pk, _p);
	
	stringstream ss;
	ss << sk;
	return ss.str();
}
