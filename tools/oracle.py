from tools.message import Message
from tools.aes import AES_ECB, AES_CBC
from tools.randomdata import randMsg
from tools.mt19937 import mt19937_32_CTR
from random import randint

rand_prefix = randMsg(0, 20)

class Oracle():
    def __init__(self, key=None, prefix=None, postfix=None):
        if key is None:
            key = randMsg(16)
        if prefix is None:
            prefix = Message(b'')
        if postfix is None:
            postfix = Message(b'')
        self.key = key
        self.prefix = prefix
        self.postfix = postfix
    
    def encryptECB(self, msg):
        plaintext = self.prefix + msg + self.postfix
        return AES_ECB(plaintext, self.key)

    def decryptECB(self, msg):
        return AES_ECB(msg, self.key, fn='decrypt')

    def encryptCBC(self, msg):
        plaintext = self.prefix + msg + self.postfix
        iv = randMsg(16)
        return AES_CBC(plaintext, self.key, iv)

    def decryptCBC(self, msg, check_pad=False):
        return AES_CBC(msg, self.key, fn='decrypt')

    def decryptAndCheckPadCBC(self, msg):
        plaintext = AES_CBC(msg, self.key, fn='decrypt')
        return plaintext.validatePad()

    def encryptCTR(self, msg):
        plaintext = self.prefix + msg + self.postfix
        return AES_CTR(plaintext, self.key)
    
    def decryptCTR(self, msg):
        return AES_CTR(plaintext, self.key)

    def encryptMT19937_32_CTR(self, msg):
        plaintext = self.prefix + msg + self.postfix
        return mt19937_32_CTR(plaintext, self.key)

    def decryptMT19937_32_CTR(self, msg):
        return mt19937_32_CTR(msg, self.key)

def ECBOracle(msg):
    """ Appends the string tools.postfix to a message, 
    then encrypts the result using AES-ECB under a fixed 
    random 16-byte key.

    Args:
        msg (string): the message to be concatenated with 
        the bytes of tools.postfix1 and then encrypted.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

    Returns: 
        string: The ascii-encoded encryption of the
        concatenation of 'msg' with the bytes of
        tools.postfix, using AES-ECB under a fixed 
        random 16-byte key.
    """
    prefix = rand_prefix
    postfix_str = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    postfix = Message(postfix_str, 'base64')

    oracle = Oracle(rand_key, prefix, postfix)
    return oracle.encryptECB(msg)
