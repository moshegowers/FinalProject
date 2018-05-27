import socket

IP_ADDRESS = '0.0.0.0'
PORT = 4921
LISTEN_COUNT = 1
RECV_LENGTH = 1024
CLOSE_CON_MSG = 'Connection with client closed.'


def run_server():
    server_socket = socket.socket()
    server_socket.bind((IP_ADDRESS, PORT))
    server_socket.listen(LISTEN_COUNT)
    listen(server_socket)


def listen(server_socket):
    while True:
        (client_socket, address) = server_socket.accept()
        try:
            data = client_socket.recv(RECV_LENGTH)
            if bytes(data).decode() == '':
                print(CLOSE_CON_MSG)
            else:
                client_socket.send(data)
                print(bytes(data).decode())
        except:
            print("The client not available")
        finally:
            client_socket.close()


def main():
    run_server()


if __name__ == "__main__":
    main()
