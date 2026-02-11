import pickle
from time import time, sleep
from socket import socket
from select import select

from .request import Request
from .response import Response

SERVER_PORT = 2048
SERVER_IP = "INSERT IP HERE"

class RawConnection:
    """
    A raw peer to peer socket.

    This class should not be used from two or more threads at the same time. 
    """

    _socket: socket
    _recv_buf: bytearray
    _recv_list: list[bytes]

    def __init__(self, s: socket):
        self._socket = s
        self._socket.setblocking(False)
        self._recv_buf = bytearray()
        self._recv_list = []

    def has_input(self) -> bool:
        return select([self._socket], [], [], 0)[0]

    def recv_raw(self) -> bytes | None:
        there_is_input = select([self._socket], [], [], 0)[0]
        if there_is_input:
            self._recv_buf.extend(self._socket.recv(65536))

        while True:
            if len(self._recv_buf) < 4:
                # the start of the message is a uint32 for the size of the message.
                break

            length = int.from_bytes(self._recv_buf[:4])
            if len(self._recv_buf) < 4 + length:
                # we should wait until the whole message is sent.
                break

            self._recv_buf = self._recv_buf[4:]

            self._recv_list.append(self._recv_buf[:length])
            self._recv_buf = self._recv_buf[length:]

        if len(self._recv_list) == 0:
            return None
        
        return self._recv_list.pop(0)

    def send_raw(self, message: bytes):
        self._socket.sendall(len(message).to_bytes(4))
        self._socket.sendall(message)

    def close(self):
        """
        Closes the socket.

        Do not use the socket after calling this function.
        """

        self._socket.close()

class ClientConnection(RawConnection):
    def recv(self) -> Response | None:
        serialized_message = self.recv_raw()
        if serialized_message == None:
            return None
        
        return pickle.loads(serialized_message)

    def send(self, message: Request):
        serialized_message = pickle.dumps(message)
        self.send_raw(serialized_message)

class ServerConnection(RawConnection):
    def recv(self) -> Request | None:
        serialized_message = self.recv_raw()
        if serialized_message == None:
            return None
        
        return pickle.loads(serialized_message)

    def send(self, message: Response):
        serialized_message = pickle.dumps(message)
        self.send_raw(serialized_message)

class ServerListener:
    _socket: socket

    def __init__(self):
        self._socket = socket()
        self._socket.bind(("0.0.0.0", SERVER_PORT))
        self._socket.listen()

    def accept(self) -> ServerConnection | None:
        """
        Accepts a connection if one is waiting.

        Does not block if theres no connection. 
        """

        conn_is_waiting, _, _ = select([self._socket], [], [], timeout=0)
        if not conn_is_waiting:
            return None
        
        conn, _ = self._socket.accept()
        return ServerConnection(conn)

def try_connect_to_server() -> ClientConnection | None:
    """
    Returns a connection to the server if possible.
    """

    s = socket()
    s.setblocking(False)

    start_time = time.time()
    while True:
        try:
            s.connect((SERVER_IP, SERVER_PORT))
            return ClientConnection(s)
        except:
            sleep(0.001)
            continue
    
    return None

