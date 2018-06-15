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

	/*_dh.UnlockComponent("Anything for 30-day trial");
	_dh.UseKnownPrime(2);*/
}

string DiffieHelman::get_p()
{
	//return _dh.p();
	stringstream ss;
	ss << _p;
	return ss.str();
}

int DiffieHelman::get_g()
{
	//return _dh.get_G();
	stringstream ss;
	ss << _g;
	return stoi(ss.str());
}

void DiffieHelman::set_pg(const char * p, int g)
{
	//_dh.SetPG(p, g);
}

string DiffieHelman::get_public_key()
{
	Integer pub;
	pub.Decode(_publicKey.BytePtr(), _publicKey.SizeInBytes());
	stringstream ss;
	ss << pub;
	return ss.str();
	//return _dh.createE(512);
}

string DiffieHelman::set_sheard_key(const char *pubKey)
{
	Integer i(pubKey), pk, sk;
	pk.Decode(_privateKey.BytePtr(), _privateKey.SizeInBytes());
	sk = a_exp_b_mod_c(i, pk, _p);
	//stringstream ss("1007236729809112577516425642247385028816751948970438338740753926430690681252935049807949806018698479441332651455475340691716082521140030245386345076551441");
	stringstream ss;
	ss << sk;
	return ss.str();
	//return _dh.findK(pubKey);
}
