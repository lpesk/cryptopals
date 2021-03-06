from tools.message import Message
from tools.bitops import XOR
from tools.aes import AES_ECB, AES_CBC, AES_CBC_IVKey, AES_CTR, keystreamCTR
from tools.randomdata import randMsg
from tools.mt19937 import mt19937_32_CTR
from tools.authentication import macSHA1, macMD4, hmacSHA1
from random import randint
from time import sleep

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

    def formMsg(self, msg):
        return self.prefix + msg + self.postfix
    
    def encryptECB(self, msg):
        return AES_ECB(self.formMsg(msg), self.key)

    def decryptECB(self, msg):
        return AES_ECB(msg, self.key, fn='decrypt')

    def encryptCBC(self, msg):
        return AES_CBC(self.formMsg(msg), self.key, iv=randMsg(16))

    def decryptCBC(self, msg, check_pad=False):
        return AES_CBC(msg, self.key, fn='decrypt')

    def encryptIVKeyCBC(self, msg):
        return AES_CBC_IVKey(self.formMsg(msg), self.key)

    def decryptIVKeyCBC(self, msg):
        return AES_CBC_IVKey(msg, self.key, fn='decrypt')

    def encryptCTR(self, msg):
        plaintext = self.prefix + msg + self.postfix
        return AES_CTR(plaintext, self.key)
    
    def decryptCTR(self, msg):
        return AES_CTR(msg, self.key)

    def editCTR(self, msg, offset, new):
        # note that offset is asserted to be nonnegative in aes.keystreamCTR
        assert(len(new) <= len(msg) - offset)
        key_bytes = keystreamCTR(self.key, len(new), offset)
        prev = msg[:offset]
        post = msg[offset + len(new):]
        insert = XOR(new, key_bytes)
        return prev + insert + post

    def encryptMT19937_32_CTR(self, msg):
        plaintext = self.prefix + msg + self.postfix
        return mt19937_32_CTR(plaintext, self.key)

    def decryptMT19937_32_CTR(self, msg):
        return mt19937_32_CTR(msg, self.key)

    def authMACSHA1(self, msg):
        plaintext = self.formMsg(msg)
        return (plaintext, macSHA1(self.key, plaintext))
    
    def checkMACSHA1(self, msg, mac):
        return (macSHA1(self.key, msg) == mac)

    def authMACMD4(self, msg):
        plaintext = self.formMsg(msg)
        return (plaintext, macMD4(self.key, plaintext))

    def checkMACMD4(self, msg, mac):
        return (macMD4(self.key, msg) == mac)

    def authHMACSHA1(self, msg):
        plaintext = self.formMsg(msg)
        return (plaintext, hmacSHA1(self.key, plaintext))

    def checkHMACSHA1(self, msg, mac):
        return (hmacSHA1(self.key, msg) == mac)
    
    def checkHMACSHA1_insecure(self, msg, hmac):
        true_hmac_bytes = Message(hmacSHA1(self.key, msg), 'hex').bytes
        test_hmac_bytes = Message(hmac, 'hex').bytes
        for (byte1, byte2) in zip(true_hmac_bytes, test_hmac_bytes):
            if byte1 != byte2:
                return False
            sleep(.05)
        if len(true_hmac_bytes) != len(test_hmac_bytes):
            return False
        else:
            return True


def ECBOracle(msg):
    """ Appends the string tools.postfix to a message, 
    then encrypts the result using AES-ECB under a fixed 
    random 16-byte key.

    Args:
        msg (Message): the message to be concatenated with 
        the bytes of tools.postfix1 and then encrypted.

    Returns: 
        Message: The  encryption of the concatenation of 'msg' with the bytes of tools.postfix, using AES-ECB under a fixed random 16-byte key.
    """
    prefix = rand_prefix
    postfix_str = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    postfix = Message(postfix_str, 'base64')

    oracle = Oracle(rand_key, prefix, postfix)
    return oracle.encryptECB(msg)
