from tools.message import Message
from random import randint

def randMsg(int1, int2=None):
    if int2 is None:
        length = int1
    else:
        length = randint(int1, int2)
    return Message(b''.join(bytes([randint(0, 255)]) for k in range(length)))
