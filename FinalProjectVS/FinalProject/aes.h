#ifndef AES_HPP_
#define AES_HPP_

#include <algorithm>
#include <iterator>
#include <vector>
#include <string>

#include "aesbase.h"

class aes{
	public:
		aes() {};
        aes(std::string & KeyWord);
        aes(std::vector<unsigned char> & KeyWord);

        std::vector< std::vector<unsigned char> > key();
        std::vector< std::vector<unsigned char> > key_inverse();
		std::vector<unsigned char> get_round_key_matrix();
        void set_key(std::vector<unsigned char> & KeyWord);
        bool Init;
        unsigned value();

		std::string Encrypt(std::string plaintext);
		std::string Decrypt(std::string plaintext);

    private:
        void _adjust_key_length(std::vector<unsigned char> & KeyWord);

        std::vector< std::vector<unsigned char> > _KeyRoundMatrix;
        std::vector< std::vector<unsigned char> > _InvKeyRoundMat;
        const std::vector<unsigned> _RoundConst = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
        const unsigned MatDim = 4;
        const unsigned Byte = 8;
        const unsigned RoundNumber = 9;
        const unsigned ByteSize = 16;
        const unsigned BitSize = 128;
        unsigned _Value;
};

#endif