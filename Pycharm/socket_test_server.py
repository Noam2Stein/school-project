from lib.socket_wrapper import ServerListener, ServerConnection
from lib.request_response import Request, LoginRequest, LoginResponse

print("creating listener")

listener = ServerListener()

print("listener created. waiting for client")

conn = listener.accept()
while conn is None:
    conn = listener.accept()

print("client connected. waiting for message")

recv = conn.recv()
while recv is None:
    recv = conn.recv()

print("message recveived. checking equality")

assert LoginRequest(**recv) == LoginRequest(auth_key=5430897456,email="yarden.cohen@america.us")

print("request is correct. sending response")

conn.send(LoginResponse(is_succees=True,incorrect_password=False,user_doesnt_exist=False))

print("response sent")