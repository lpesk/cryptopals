from tools.message import Message
from random import randint, choice
from string import printable

def randBytes(min_len, max_len=None):
    if max_len is None:
        length = min_len
    else:
        length = randint(min_len, max_len)
    return b''.join(bytes([randint(0, 255)]) for _ in range(length))

def randPrintableAscii(min_len, max_len=None):
    if max_len is None:
        length = min_len
    else:
        length = randint(min_len, max_len)
    return ''.join(choice(printable) for _ in range(length))

def randMsg(min_len, max_len=None):
    return Message(randBytes(min_len, max_len))
