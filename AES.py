import base64
from aes_test import aes
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


class AESCipher:

    def __init__(self, key):
        self.key = key[:32]
        print(self.key)

    def encrypt(self, raw):
        raw = pad(raw)
        iv = b'1111111111111111'  # Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(raw))
        # return iv + cipher.encrypt(raw);

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = b'1111111111111111'
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        x = unpad(cipher.decrypt(enc))
        return x
