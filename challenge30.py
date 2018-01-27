from tools.authentication import macMD4, BadMAC
from tools.authattacks import extendMACMD4
from tools.message import Message
from tools.md4 import MD4
from tools.randomdata import randMsg
from tools.oracle import Oracle
from tools.token import Token, InvalidToken
from Crypto.Hash import MD4 as true_MD4

# test md4 implementation against pycrypto's md4
trials = 10

for trial in range(trials):
    m = randMsg(0, 1000)

    print("\nTrial %d of %d:" % (trial + 1, trials))
    print("\nTesting md4 hash of", m)

    test_digest = MD4().hash(m)
    print("Test digest:", test_digest)

    s = true_MD4.new()
    s.update(m.bytes)
    true_digest = s.hexdigest()
    print("True digest:", true_digest)

    assert(test_digest == true_digest)

# demonstrate implementation of md4 keyed mac
key = randMsg(16)
msg = randMsg(20)
mac = macMD4(key, msg)
print("\nA sample use of an MD4 keyed MAC:")
print("Key:", key)
print("Msg:", msg)
print("MAC:", mac)

prefix = Message(b'comment1=cooking%20MCs;userdata=')
postfix = Message(b';comment2=%20like%20a%20pound%20of%20bacon')

class CookieFactoryMACMD4():
    def __init__(self):
        self.oracle = Oracle(None, prefix, postfix)
        self.sep_field = Message(b';')
        self.sep_key = Message(b'=')
        self.default_keys = [Message(b'comment1'), Message(b'userdata'), Message(b'comment2')]

    def newAuthCookie(self, user_data):
        user_data_msg = Message(user_data, 'ascii')
        return self.oracle.authMACMD4(user_data_msg)

    def isAdminAuthCookie(self, mac_pair):
        (cookie, mac) = mac_pair
        if not self.oracle.checkMACMD4(cookie, mac):
            raise BadMAC
        try:
            token = Token.fromMsg(cookie, Message(b';'), Message(b'='))
        except IndexError:
            raise InvalidToken
        try:
            return token.data[Message(b'admin')] == Message(b'true')
        except KeyError:
            return False

if __name__ == '__main__':
    min_key_len = 0
    max_key_len = 32

    factory = CookieFactoryMACMD4()
    username = 'notatallsneaky'
    (cookie, mac) = factory.newAuthCookie(username)
    print("\nOriginal cookie plaintext is:\n\t",cookie)
    print("...its keyed MAC is:\n\t",mac)
    print("...are we admin?\n\t", factory.isAdminAuthCookie((cookie, mac)))
    
    add_text = Message(b';admin=true')
    print("\nExtending the MAC with:\n\t",add_text)

    is_admin = False
    key_len = min_key_len
    while not is_admin:
        if key_len > max_key_len:
            raise Exception("Key length not found in range [%d, %d]" % (min_key_len, max_key_len))
        try:
            test_pair = extendMACMD4(cookie, mac, add_text, key_len)
            is_admin = factory.isAdminAuthCookie(test_pair)
        except BadMAC:
            pass
        key_len += 1
    
    (new_cookie, new_mac) = test_pair
    print("Key length is", key_len - 1)
    print("New cookie plaintext is:\n\t",new_cookie)
    print("...its keyed MAC is:\n\t", new_mac)
    print("...are we admin?\n\t", factory.isAdminAuthCookie((new_cookie, new_mac)))
