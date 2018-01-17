from tools.message import Message
from tools.aes import AES_CBC_IVKey
from tools.bitops import XOR
from tools.oracle import Oracle
from tools.token import Token
from contextlib import redirect_stderr
import sys

prefix = Message(b'comment1=cooking%20MCs;userdata=')
postfix = Message(b';comment2=%20like%20a%20pound%20of%20bacon')

class InvalidAscii(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "Message contains invalid ASCII characters")
        sys.stderr.buffer.write(msg.bytes+b'\n')

class CookieFactoryIVKeyCBC():
    def __init__(self):
        self.oracle = Oracle(None, prefix, postfix)
        self.sep_field = Message(b';')
        self.sep_key = Message(b'=')
        self.default_keys = [Message(b'comment1'), Message(b'userdata'), Message(b'comment2')]
        
    def newCookie(self, user_input):
        user_input_msg = Message(user_input, 'ascii')
        return self.oracle.encryptIVKeyCBC(user_input_msg)

    def isAdminCookie(self, msg):
        decr_msg = self.oracle.decryptIVKeyCBC(msg)
        if not decr_msg.validateAscii():
            raise InvalidAscii(decr_msg)
        try:
            token = Token.fromMsg(decr_msg, Message(b';'), Message(b'='))
        except IndexError:
            raise InvalidToken
        try:
            return token.data[Message(b'admin')] == Message(b'true')
        except KeyError:
            return False

def breakIVKeyCBC(factory):
    block_size = 16
    user_input = 'A' * 16 * 3
    cookie = factory.newCookie(user_input)
    cookie_first_block = cookie[:block_size]
    broken_cookie = cookie_first_block + Message(b'\x00' * 16) + cookie_first_block

    with open('data/challenge27.log', 'w') as error_log:
        with redirect_stderr(error_log):
            try:
                factory.isAdminCookie(broken_cookie)
            except InvalidAscii:
                pass

    with open('data/challenge27.log', 'rb') as error_log:
        decrypt = Message(bytes(error_log.read(block_size * 3)))

    decrypt_first_block = decrypt[:block_size]
    decrypt_third_block = decrypt[-block_size:]
    key = XOR(decrypt_first_block, decrypt_third_block)
    return(key)

if __name__ == '__main__':
    factory = CookieFactoryIVKeyCBC()
    key = breakIVKeyCBC(factory)
    print("Recovered key:", key)
    test_cookie = factory.newCookie('A' * 10)
    print("Encrypted test cookie:", test_cookie)
    test_decrypt = AES_CBC_IVKey(test_cookie, key, fn='decrypt')
    print("Decryption with recovered key:", test_decrypt)
