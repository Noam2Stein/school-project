from .lib.socket_wrapper import ClientConnection, try_connect_to_server
from .lib.request_response import LoginRequest, LoginResponse

conn = try_connect_to_server()
while conn is None:
    conn = try_connect_to_server()

conn.send(LoginRequest(auth_key=5430897456,email="yarden.cohen@america.us"))

recv = conn.recv()
while recv is None:
    recv = conn.recv()

assert recv == LoginResponse(is_succees=True,password_is_correct=True)
