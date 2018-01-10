from tools.message import Message
from tools.oracle import Oracle
from tools.token import Token, InvalidToken
from collections import OrderedDict
from random import randint

uid_min = 0
uid_max = 1000

class Authorizer():
    
    def __init__(self):
        self.oracle = Oracle()
        self.sep_field = Message(b';')
        self.sep_key = Message(b'=')
        self.default_keys = [Message(b'email'), Message(b'uid'), Message(b'role')]

    def newUserProfile(self, email):
        user_data = OrderedDict.fromkeys(self.default_keys)
        user_data[Message(b'email')] = Message(email, 'ascii')
        user_data[Message(b'uid')] = Message(str(randint(uid_min, uid_max)), 'ascii')
        user_data[Message(b'role')] = Message(b'user')
        token = Token(user_data, self.sep_field, self.sep_key)
        encr_token = self.oracle.encryptECB(token.msg)
        return encr_token

    def validateProfile(self, msg):
        decr_msg = self.oracle.decryptECB(msg).stripPad()
        token = Token.fromMsg(decr_msg, Message(b';'), Message(b'='))
        is_admin = False
        try:
            email = token.data[Message(b'email')]
            uid = token.data[Message(b'uid')]
            role = token.data[Message(b'role')]
            if role == Message(b'admin'):
                is_admin = True
            print("Logging in as %s with email %s and UID %s..." % (role.ascii(), email.ascii(), uid.ascii()))
            return is_admin
        except KeyError:
            raise InvalidToken

def forgeAdminProfile(auth, verbose=False):
    """ Produce a message which passes validation as an admin
    profile under the encrypted-profile scheme given by 
    tools.newEncrProfile and tools.validateProfile.
    
    Method:
    The strings produced by tools.newEncrProfile are 
    AES-ECB encryptions (using a fixed, unknown key)
    of tokens produced by tools.newProfile. See the
    docstring of tools.newProfile for the structure of
    those tokens.

    Since the encryption of a given block of 
    a plaintext with AES-ECB depends only on that
    block and on the key, we can "cut and paste"
    blocks of encrypted profiles to create strings
    which decrypt to the corresponding patchwork
    plaintext.

    We'll create 2 profiles in which the block
    divisions are conveniently located, select parts 
    of each, and paste them together. To do this,
    we need to make an assumption about how many digits
    are in the user ID number which tools.newProfile
    randomly generates from the range [1, 1000]. Let's 
    assume the UID has 3 digits. The 2 profiles we create
    are the encryptions of x and y:
    
    x: 
    email=AAAAAAAAAAadminPPPPPPPPPPP&uid=???&role=user
    ^               ^               ^               ^
    x[0]            x[1]            x[2]           x[3]
    
    y:
    email=AAAAAAAAAAAA&uid=!!!&role=user
    ^               ^               ^
    y[0]            y[1]            y[2]    
    
    Let X denote the AES-ECB encryption of x and Y the
    encryption of y. Our forged profile is the message
    
    Y[0] + Y[1] + X[1]
    
    which decrypts to the valid admin profile
    
    email=AAAAAAAAAAAA&uid=!!!&role=adminPPPPPPPPPPP
    ^               ^               ^              
    y[0]           y[1]            x[1] 
    
    To account for the fact that the UID might not have 
    exactly 3 digits, we'll keep generating profiles of
    this form (with different random UIDs each time) until
    success.
    
    Returns: 
    dict (string: string): a dictionary of keys 
    and values represented by the a decrypted admin
    token.
    """
    is_admin = False
    while not is_admin:
        profile0 = auth.newUserProfile('A'*10 + 'admin' + '\x0b'*11)
        profile1 = auth.newUserProfile('A'*12)
        forged = profile1[:32] + profile0[16:32]
        is_admin = auth.validateProfile(forged)
        if verbose:
            print("Success") if is_admin else print("Failed")
    return forged

if __name__ == '__main__':
    auth = Authorizer()
    forgeAdminProfile(auth, verbose=True)

        
