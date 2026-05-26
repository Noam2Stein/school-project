import base64


def bytes_to_str(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).decode("ascii")


def str_to_bytes(data: str) -> bytes:
    # normalize
    data = data.strip()

    # fix missing padding (very common bug source)
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)

    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Invalid base64 input: {data[:50]}") from e
