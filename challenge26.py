from tools.message import Message
from tools.token import Token
from tools.oracle import Oracle
from tools.aesattacks import findAffixLengthCTR
from tools.bitops import XOR

prefix = Message(b'comment1=cooking%20MCs;userdata=')
postfix = Message(b';comment2=%20like%20a%20pound%20of%20bacon')

class CookieFactoryCTR():
    def __init__(self):
        self.oracle = Oracle(None, prefix, postfix)
        self.sep_field = Message(b';')
        self.sep_key = Message(b'=')
        self.default_keys = [Message(b'comment1'), Message(b'userdata'), Message(b'comment2')]
        
    def newCookie(self, user_input):
        user_input_msg = Message(user_input, 'ascii')
        return self.oracle.encryptCTR(user_input_msg)

    def isAdminCookie(self, msg):
        decr_msg = self.oracle.decryptCTR(msg)
        try:
            token = Token.fromMsg(decr_msg, Message(b';'), Message(b'='))
        except IndexError:
            raise InvalidToken
        try:
            return token.data[Message(b'admin')] == Message(b'true')
        except KeyError:
            return False

def forgeAdminCookieCTR(factory):
    cookie = factory.newCookie('\x00' * 18)
    (prefix_len, suffix_len) = findAffixLengthCTR(factory.oracle)
    new_text = Message(b'\x00' * prefix_len + b'he;ll=o;admin=true' + b'\x00' * suffix_len)
    forged = XOR(new_text, cookie)
    return forged

if __name__ == '__main__':
    factory = CookieFactoryCTR()
    forged = forgeAdminCookieCTR(factory)
    is_admin = factory.isAdminCookie(forged)
    assert(is_admin)
    print("Success!")
     
