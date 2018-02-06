from tools.message import Message
import pytest

def hexToBase64(msg_hex):
    return Message(msg_hex, 'hex').base64()
