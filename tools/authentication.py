from tools.message import Message
from tools.md4 import MD4
from tools.sha1 import SHA1

class BadMAC(Exception):
    def __init__(self):
        Exception.__init__(self, "Authentication failed.")

def macSHA1(key, msg):
    return SHA1().hash(key + msg)

def macMD4(key, msg):
    return MD4().hash(key + msg)
