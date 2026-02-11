from .socket_wrapper import ServerConnection
from .request import Request

class Client:
    _conn: ClientConnection

    def __init__(self, conn: ServerConnection):
        self.conn = conn

def handle_next_request(client: Client):
    # TODO: handle the request.
    pass
