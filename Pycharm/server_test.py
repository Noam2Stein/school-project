from lib.socket_wrapper import try_connect_to_server
from lib.request_response import (
    LoginRequest, LoginResponse,
    SignupRequest, SignupResponse,
    FetchRequest, FetchResponse,
    PushRequest, PushResponse,
    SendRequest, SendResponse,
    ItemRequest, ItemResponse,
    CreateItemRequest, CreateItemResponse,
    EncryptItemRequest, EncryptItemResponse,
    ReleaseItemRequest, ReleaseItemResponse,
)
from datetime import datetime


def wait_for_response(conn):
    """Helper function to wait for a non-blocking response."""
    response = conn.recv()
    while response is None:
        response = conn.recv()
    return response


print("Trying to find server...")
conn = try_connect_to_server()
while conn is None:
    conn = try_connect_to_server()

print("Server found. Starting tests...")

# Define static username and password
email = "testuser@domain.com"
auth_key = 5430897456  # Use some hashed password value

# ---------------------------
# 1. Signup Test
print("Testing SignupRequest...")
signup_request = SignupRequest(
    email=email,
    auth_key=auth_key,
    private_info="private_info_data",  # Use a UTF-8 string
    public_key=346789457098345
)
conn.send(signup_request)
signup_response = wait_for_response(conn)  # Wait for the response
assert SignupResponse(**signup_response) == SignupResponse(is_succees=True, email_is_taken=False)
print("Signup successful.")

# ---------------------------
# 2. Login Test
print("Testing LoginRequest...")
login_request = LoginRequest(email=email, auth_key=auth_key)
conn.send(login_request)
login_response = wait_for_response(conn)  # Wait for the response
assert LoginResponse(**login_response) == LoginResponse(is_succees=True, incorrect_password=False,
                                                        user_doesnt_exist=False)
print("Login successful.")

# ---------------------------
# 3. Fetch Test
print("Testing FetchRequest...")
fetch_request = FetchRequest()
conn.send(fetch_request)
fetch_response = wait_for_response(conn)  # Wait for the response
assert FetchResponse(**fetch_response).is_success == True
print("Fetch successful.")

# ---------------------------
# 4. Push Test
print("Testing PushRequest...")
push_request = PushRequest(private_info="new_private_info", messages=[])  # UTF-8 string
conn.send(push_request)
push_response = wait_for_response(conn)  # Wait for the response
assert PushResponse(**push_response).is_succees == True
print("Push successful.")

# ---------------------------
# 5. Send Message Test
print("Testing SendRequest...")
send_request = SendRequest(target_email="anotheruser@domain.com", content="Hello, world!")  # UTF-8 string
conn.send(send_request)
send_response = wait_for_response(conn)  # Wait for the response
print(SendResponse(**send_response))
assert SendResponse(**send_response).is_succees == True
print("Send message successful.")

# ---------------------------
# 6. Item Request Test
print("Testing ItemRequest...")
item_id = "item123"  # Use a UTF-8 string for the ID
item_request = ItemRequest(id=item_id, auth_key=auth_key)
conn.send(item_request)
item_response = wait_for_response(conn)  # Wait for the response
assert ItemResponse(**item_response).is_success == True
print("Item request successful.")

# ---------------------------
# 7. Create Item Test
print("Testing CreateItemRequest...")
create_item_request = CreateItemRequest(contents="encrypted_item_data", auth_key=auth_key)  # UTF-8 string
conn.send(create_item_request)
create_item_response = wait_for_response(conn)  # Wait for the response
assert CreateItemResponse(**create_item_response).is_success == True
print("Item creation successful.")

# ---------------------------
# 8. Encrypt Item Test
print("Testing EncryptItemRequest...")
encrypt_item_request = EncryptItemRequest(
    id=item_id,
    auth_key=auth_key,
    public_key="some_public_key",  # UTF-8 string
    prefix="encrypted_prefix"  # UTF-8 string
)
conn.send(encrypt_item_request)
encrypt_item_response = wait_for_response(conn)  # Wait for the response
assert EncryptItemResponse(**encrypt_item_response).is_success == True
print("Item encryption successful.")

# ---------------------------
# 9. Release Item Test
print("Testing ReleaseItemRequest...")
release_item_request = ReleaseItemRequest(
    id=item_id,
    auth_key=auth_key,
    info="release_key_info",  # UTF-8 string
    expires=datetime(2026, 4, 4, 12, 0)
)
conn.send(release_item_request)
release_item_response = wait_for_response(conn)  # Wait for the response
assert ReleaseItemResponse(**release_item_response).is_success == True
print("Item release successful.")

# All tests passed
print("All tests passed successfully.")