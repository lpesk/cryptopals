from tools.bitops import XOR
from tools.message import Message
from tools.oracle import Oracle
from tools.token import Token, InvalidToken
from collections import OrderedDict

prefix = Message(b'comment1=cooking%20MCs;userdata=')
postfix = Message(b';comment2=%20like%20a%20pound%20of%20bacon')

class CookieFactoryCBC():
    def __init__(self):
        self.oracle = Oracle(None, prefix, postfix)
        self.sep_field = Message(b';')
        self.sep_key = Message(b'=')
        self.default_keys = [Message(b'comment1'), Message(b'userdata'), Message(b'comment2')]
        
    def newCookie(self, user_input):
        user_input_msg = Message(user_input, 'ascii')
        return self.oracle.encryptCBC(user_input_msg)

    def isAdminCookie(self, msg):
        decr_msg = self.oracle.decryptCBC(msg)
        try:
            token = Token.fromMsg(decr_msg, Message(b';'), Message(b'='))
        except IndexError:
            raise InvalidToken
        try:
            return token.data[Message(b'admin')] == Message(b'true')
        except KeyError:
            return False

def forgeAdminCookieCBC(factory, try_byte):
    """ Produce a string which is validated as an admin token
    by tools.validateAuthString, without knowledge of that
    function's decryption key.

    Method:
        We'll produce an encryption of the following
        string (shown here with '|'s inserted to show
        divisions into blocks of 16 bytes):

'00000000000000000|comment1=cooking|%20MCs;userdata=|;comment2=%20like|%20a%20pound%20of|%20bacon'

        using tools.newAuthString (with empty input). Then
        we'll XOR this encrypted string with a second string
        such that the decryption of the modified string will
        have ";admin=heckyeahX" (where X is some character) as
        its 4th block.

        The reason we can do this is that flipping the j-th
        bit in the k-th block of an AES-CBC ciphertext will
        flip the j-th bit in the (k + 1)-th block of its
        decryption. (Notice that the k-th block of the cipher-
        text gets XOR'd with the decryption of the (k + 1)-th
        block of the ciphertext to produce the (k + 1)-th block
        of the plaintext!).

        Specifically, we'll modify the 3rd block of the
        ciphertext by XORing it with XOR(';admin=heckyeahX',
        ';comment2=%20lik'), where X runs over some range of 
        characters until the decryption of the modified string
        parses properly. If the decryption parses, it will also
        be validated as an admin token because it contains
        'admin' as a key.

        The reason our first choice of X might not succeed is 
        that, depending on the key (tools.rand_key), the 
        decryption of the 3rd block might contain some meta-
        characters which prevent the decrypted string from 
        parsing properly. In practice, this method usually 
        succeeds in one or two tries. 

    Arg:
        verbose (bool): if True, print some information about 
        the intermediate steps; silent if False.

    Returns:
        bool: True if a string which is validated as an admin
        token was successfully produced; False if not.
    """
    cookie = factory.newCookie('')
    current = Message(b';comment2=%20lik')
    new_cookie = Message(b';comment2=%20lik')
    wish = Message(b';admin=true;xx=') + Message(bytes([try_byte]))
    diff = XOR(current, wish)
    forged = cookie[:32] + XOR(cookie[32:48], diff) + cookie[48:]
    return forged

if __name__ == '__main__':
    factory = CookieFactoryCBC()
    try_byte = 65
    is_admin = False
    while try_byte < 127 and not is_admin:
        forged = forgeAdminCookieCBC(factory, try_byte)
        try:
            is_admin = factory.isAdminCookie(forged)
        except InvalidToken:
            pass
        try_byte += 1
    if try_byte < 127:
        print("Success in %d try(s)!" % (try_byte - 65))
    else:
        print("Fail!")
    
