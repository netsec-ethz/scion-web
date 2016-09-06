
import base64


def to_b64(bytes_input):
    return base64.b64encode(bytes_input).decode('utf-8')


def from_b64(string_input):
    return base64.b64decode(string_input)
