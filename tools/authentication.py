from tools.message import Message
from tools.sha1 import SHA1

def macSHA1(key, msg):
    return SHA1().hash(key + msg)
