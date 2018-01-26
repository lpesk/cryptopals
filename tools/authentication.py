from tools.message import Message
from tools.sha1 import SHA1

class BadMAC(Exception):
    def __init__(self):
        Exception.__init__(self, "Authentication failed.")

def macSHA1(key, msg):
    return SHA1().hash(key + msg)
