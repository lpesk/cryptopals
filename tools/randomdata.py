from tools.message import Message

from base64 import b16encode, b64encode
from hypothesis.strategies import integers
from random import randint, choice
from string import printable

# for now, constrain testing time by bounding length of test messages
# TODO: improve testing time and/or limits on testing time
min_msg_len = 0
max_msg_len = 1000

def bddIntegers(min_value=None, max_value=None):
    if min_value is None:
        min_value = min_msg_len
    if max_value is None:
        max_value = max_msg_len
    return integers(min_value, max_value)

def randBytes(min_len, max_len=None):
    if max_len is None:
        length = min_len
    else:
        length = randint(min_len, max_len)
    return b''.join(bytes([randint(0, 255)]) for _ in range(length))

def randBase64(min_len, max_len=None):
    return b64encode(randBytes(min_len, max_len)).decode('utf-8')

def randBin(min_len, max_len=None):
    rand_bytes = randBytes(min_len, max_len)
    return ''.join(bin(byt).lstrip('0b').rjust(8, '0') for byt in rand_bytes)

def randHex(min_len, max_len=None):
    return b16encode(randBytes(min_len, max_len)).lower().decode('utf-8')

def randMsg(min_len, max_len=None):
    return Message(randBytes(min_len, max_len))

def randPrintableMsg(min_len, max_len=None):
    if max_len is None:
        length = min_len
    else:
        length = randint(min_len, max_len)
    return Message(''.join(choice(printable) for _ in range(length)), 'ascii')
