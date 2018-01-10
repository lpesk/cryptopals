from tools.message import Message
from tools.oracle import Oracle
from tools.aesattacks import isAES_ECB
from tools.randomdata import randMsg
from random import randint

def AESOracle(msg, test_mode=False):
    """ An oracle which does the following, given a message:
    chooses an integer m uniformly from [5, 10] and prepends a
    random string of m bytes to a message, then chooses an
    integer n uniformly from [5, 10] and appends a random
    string of n bytes to the message; generates a random
    16-byte key; then flips a fair coin and encrypts the
    enlarged message with either AES-ECB or AES-CBC (using
    another random 16-byte string as the IV) depending on the
    result.

    The oracle can be used in a simple model of a chosen-
    plaintext attack on an unknown cipher. To verify the 
    success of such an attack, the function has an optional
    "test mode" which exposes the mode of AES used for
    each encryption.

    Args:
        msg (string): the message to be affixed-to and
        encrypted.

        msg_format (string): the format in which the bytes
        of 'filename' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.
    
        test_mode (bool): if test_mode=True, the function
        returns a boolean together with each encryption 
        which reveals which mode of AES was used. If
        test_mode=False, encryption mode is not revealed.

    Returns:
        (if test_mode=False) string : the encryption using
        either AES_ECB or AES_CBC, and a random key (and IV,
        if applicable), of the concatenation of 'msg' with 
        random pre/suffixes of small random length.

        (if test_mode=True) tuple (bool, string): string arg
        is as described in the case test_mode=False. bool arg
        is True if AES-ECB was used, False if AES-CBC was used.
    """
    prefix = randMsg(5, 10)
    postfix = randMsg(5, 10)
    oracle = Oracle(None, prefix, postfix)

    coin = randint(0, 1)
    if coin:
        ciphertext = oracle.encryptECB(msg)
    else:
        ciphertext = oracle.encryptCBC(msg)
    if test_mode:
        return (coin, ciphertext)
    else:
        return ciphertext

if __name__ == '__main__':
    
    trials = 10
    msg = Message(b'A'*16*4)

    for trial in range(trials):
        (is_ecb, ciphertext) = AESOracle(msg, test_mode=True)
        guess_is_ecb = isAES_ECB(ciphertext)
        guess = 'ECB' if isAES_ECB(ciphertext) else 'CBC'
        print("Trial %d of %d: guess = %s correct? %s" % (trial + 1, trials, guess, guess_is_ecb == is_ecb))
    print("Done")
