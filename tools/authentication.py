from tools.message import Message
from tools.bitops import XOR
from tools.md4 import MD4
from tools.sha1 import SHA1

class BadMAC(Exception):
    def __init__(self):
        Exception.__init__(self, "Authentication failed.")

def macSHA1(key, msg):
    return SHA1().hash(key + msg)
    
def macMD4(key, msg):
    return MD4().hash(key + msg)

def hmacSHA1(key, msg):
    s = SHA1()
    block_size = 64
    hash_size = 20
    if len(key) > block_size:
        key = Message(s.hash(key), 'hex')
    key += Message(b'\x00' * (block_size - len(key)))    
    outer_key = XOR(key, Message(b'\x5c' * block_size))
    inner_key = XOR(key, Message(b'\x36' * block_size))
    inner_msg = Message(s.hash(inner_key), 'hex') + msg
    hmac = s.hash(outer_key + inner_msg)
    return hmac
