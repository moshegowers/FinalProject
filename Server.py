import socket
import pyDH
from AES import AESCipher
import threading
import msvcrt

IP_ADDRESS = '127.0.0.1'
PORT = 4921
LISTEN_COUNT = 1
RECV_LENGTH = 1024
CLOSE_CON_MSG = 'Connection with client closed.'


class Server:
    def __init__(self):
        try:
            self.dh = pyDH.DiffieHellman()
            self.private_key = self.dh.get_private_key()
            self.public_key = self.dh.gen_public_key()
            self.shared_key = None
            self.todo = ''
        except ValueError as e:
            print("Cannot initialized")
            return

    def get_input(self):
        if msvcrt.kbhit():
            key = ord(msvcrt.getche())
            real_key = chr(key)
            if key != 13:
                self.todo += real_key

    def set_todo(self, to_do):
        self.todo = to_do

    def listen(self, server_socket):
        while True:
            (client_socket, address) = server_socket.accept()
            try:
                data_bytes = client_socket.recv(RECV_LENGTH)
                data = None
                try:
                    data = bytes(data_bytes).decode()
                except:
                    pass
                if data is not None and data == '':
                    print(CLOSE_CON_MSG)
                else:
                    if data is not None and data.split()[0] == "1":
                        self.p = int(data.split()[1])
                        self.g = int(data.split()[2])
                        # self.dh.SetPG(data.split()[1], int(data.split()[2]))
                        self.public_key = pow(self.g, self.private_key, self.p)
                        client_socket.send(str("2 " + str(self.public_key)).encode())
                    elif data is not None and data.split()[0] == "2":
                        # self.public_key = self.dh.createE(512)
                        # self.shared_key = self.dh.findK(data.split()[1])
                        self.shared_key = pow(int(data.split()[1]), self.private_key, self.p)
                        print(self.shared_key)
                        client_socket.send(str("2 " + str(self.public_key)).encode())
                        print("key changed!")
                        self.shared_key = 1007236729809112577516425642247385028816751948970438338740753926430690681252935049807949806018698479441332651455475340691716082521140030245386345076551441
                    else:
                        cipher = AESCipher(str(self.shared_key))
                        data_decrypt = cipher.decrypt(data)  # .decode()
                        print(data_decrypt[2:])
                        if data_decrypt.split()[0] == "3":
                            client_socket.send(cipher.encrypt(self.todo.encode()))
                        elif data_decrypt.split()[0] == "4":
                            self.result = data_decrypt[2:]
                            client_socket.send(cipher.encrypt(b'Thanks'))
                # client_socket.close()
            except ValueError as e:
                print("The client not available")
            finally:
                client_socket.close()

    def run(self):
        server_socket = socket.socket()
        server_socket.bind((IP_ADDRESS, PORT))
        server_socket.listen(LISTEN_COUNT)
        threading.Thread(target=self.listen, args=(server_socket, )).start()
        # t1.join()
        while True:
            self.get_input()


def main():
    server = Server()
    server.run()


if __name__ == "__main__":
    main()
