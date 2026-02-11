from .lib.socket_wrapper import ServerListener, ServerConnection
from .lib.request_response import LoginRequest, LoginResponse

listener = ServerListener()

conn = listener.accept()
while conn is None:
    conn = listener.accept()

recv = conn.recv()
while recv is None:
    recv = conn.recv()

assert recv == LoginRequest(auth_key=5430897456,email="yarden.cohen@america.us")

conn.send(LoginResponse(is_succees=True,password_is_correct=True))



