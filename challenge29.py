from tools.message import Message
from tools.sha1 import SHA1
from tools.authentication import macSHA1
from tools.authattacks import extendMACSHA1
from tools.oracle import Oracle
from tools.token import Token, InvalidToken

prefix = Message(b'comment1=cooking%20MCs;userdata=')
postfix = Message(b';comment2=%20like%20a%20pound%20of%20bacon')

class CookieFactoryMACSHA1():
    def __init__(self):
        self.oracle = Oracle(None, prefix, postfix)
        self.sep_field = Message(b';')
        self.sep_key = Message(b'=')
        self.default_keys = [Message(b'comment1'), Message(b'userdata'), Message(b'comment2')]

    def newAuthCookie(self, user_data):
        user_data_msg = Message(user_data, 'ascii')
        return self.oracle.authMACSHA1(user_data_msg)

    def isAdminAuthCookie(self, mac_pair):
        (cookie, mac) = mac_pair
        if not self.oracle.checkMACSHA1(cookie, mac):
            raise Exception("Failed to authenticate cookie")
        try:
            token = Token.fromMsg(cookie, Message(b';'), Message(b'='))
        except IndexError:
            raise InvalidToken
        try:
            return token.data[Message(b'admin')] == Message(b'true')
        except KeyError:
            return False

if __name__ == '__main__':
    factory = CookieFactoryMACSHA1()
    username = 'notatallsneaky'
    (cookie, mac) = factory.newAuthCookie(username)
    print("\nOriginal cookie plaintext is:\n\t",cookie)
    print("...its keyed MAC is:\n\t",mac)
    print("...are we admin?\n\t", factory.isAdminAuthCookie((cookie, mac)))
    
    add_text = Message(b';admin=true')
    (new_cookie, new_mac) = extendMACSHA1(cookie, mac, add_text, 16)
    print("\nExtending the MAC with:\n\t",add_text)
    print("New cookie plaintext is:\n\t",new_cookie)
    print("...its keyed MAC is:\n\t", new_mac)
    print("...are we admin?\n\t", factory.isAdminAuthCookie((new_cookie, new_mac)))
