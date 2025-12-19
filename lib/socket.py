import pickle
from socket import socket
from select import select

# TODO: replace pickle to protect against RCE
# TODO: add TLS
# TODO: consider a better of handling large messages

class Socket[I, O]:
    def __init__(self, s: socket):
        self._socket = s
        self._in_buf = bytearray()
        self._in = []
    
    def recv(self) -> I | None:
        if self._socket == None:
            raise RuntimeError("socket is closed")

        if select([self._socket], [], [], 0)[0]:
            self._in_buf.extend(self._socket.recv(65536))

        while len(self._in_buf) >= 4:
            length = int.from_bytes(self._in_buf[:4])
            if len(self._in_buf) < 4 + length:
                break

            serialized_value = self._in_buf[4:4+length]
            self._in_buf = self._in_buf[4+length:]
            
            self._in.append(pickle.loads(serialized_value))

        if len(self._in) > 0:
            return self._in.pop(0)
        else:
            return None
    
    def send(self, value: O):
        if self._socket == None:
            raise RuntimeError("socket is closed")
    
        serialized_value = pickle.dumps(value)
        self._socket.sendall(len(serialized_value).to_bytes(4, "big"))
        self._socket.sendall(serialized_value)
    
    def close(self):
        if self._socket == None:
            raise RuntimeError("socket is already closed")
        
        self._socket.close()
        self._socket = None
