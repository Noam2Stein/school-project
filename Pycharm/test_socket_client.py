from lib.socket_wrapper import ClientConnection, try_connect_to_server
from lib.request_response import LoginRequest, LoginResponse

print("trying to find server")

conn = try_connect_to_server()
while conn is None:
    conn = try_connect_to_server()

print("server found. sending message")

conn.send(LoginRequest(auth_key=5430897456,email="yarden.cohen@america.us"))

print("message sent. waiting for response")

recv = conn.recv()
while recv is None:
    recv = conn.recv()

print("response recveived. checking equality")

assert LoginResponse(**recv) == LoginResponse(is_succees=True,incorrect_password=False,user_doesnt_exist=False)
print("everything works")
