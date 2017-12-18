#######################################################
########## tools for cryptopals challenges ############
#######################################################

# 0. Global variables and constants
#     valid_formats, valid_fns, rand_key, rand_prefix,
#     postfix, auth_prefix, auth_postfix, set3ch17_ctexts
# 1. Exception classes
#     BadPad, InvalidFormat, InvalidMode, InvalidProfile,
#     InvalidAssumptions
# 2. Conversions between byte representations
#     decode, encode, decToLitEndHex
# 3. Bitwise operations on strings
#      XOR, hamDist
# 4. Encryption and decryption functions
#      repXOR, pad, stripPad, validatePadAES_CBC, 
#      blockify, AES_ECB, AES_ECBFile, AES_CBC,
#      newBlockAES_CBC, AES_CBCFile, AES_CTR
# 5. Toy applications
#      encrOracle, ECBOracle, CBCOracle, quoteChars,   
#      parseProfile, newProfile, newEncrProfile, 
#      validateProfile, newAuthString, validateAuthString
# 6. Tools for breaking stuff
#  i. Frequency analysis tools
#      scoreText, scanKeys, scanKeysFile, guessKeySize,
#      guessRepXORKey, breakRepXOR
# ii. Attacks on AES-ECB
#      isAES_ECB, isAES_ECBFile, isUsingAES_ECB, 
#      test_isUsingAES_ECB, findBlockSize, prefixBlocks,
#      prefixOffset, prefixLength, postfixLength, 
#      decryptPostfixByteECB, decryptPostfixECB,
#      forgeAdminProfile, 
# iii. Attacks on AES-CBC
#      forgeAuthString, paddingOracleByte, 
#      paddingOracleBlock, paddingOracle, decryptSeries
# iv. Attacks on RNGs

import base64
import random
import time
from Crypto.Cipher import AES
from math import ceil
from sys import stdout

######### 0. Global variables and constants ##############

""" valid_formats: list of valid format options for all 
functions operating on strings.
"""
valid_formats = ['ascii', 'hex', 'base64']

""" valid_fns: list of valid operation options for ciphers.
"""
valid_fns = ['encrypt', 'decrypt']

# randBytes: needed to define rand_key and rand_prefix
def randBytes(size):
    """ Returns a string, of user-specified length, of random
    bytes. Uses random.randint to choose each byte. 

    Args:
        size (int): the desired length of the string of random
        bytes.

    Returns:
        string: a string of random bytes, of length 'size'.
    """
    rand_btarr = bytearray([random.randint(0, 127) for i in range(size)])
    rand_str = str(rand_btarr)
    return rand_str

rand_key = randBytes(16)

rand_prefix = randBytes(random.randint(1, 128))

postfix = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'

auth_prefix = 'comment1=cooking%20MCs;userdata='

auth_postfix = ';comment2=%20like%20a%20pound%20of%20bacon'

set3ch17_ctexts = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=', 'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=', 'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==', 'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==', 'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==', 'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=', 'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

##################### 1. Exceptions #####################

class BadPad(Exception):
    """ Exception raised when an attempt to interpret 
    the tail of a string as PKCS#7 standard padding
    has failed. 
    """
    def __init__(self):
        Exception.__init__(self, "Incorrect padding")

class InvalidFormat(Exception):
    """ Exception raised when an invalid string is
    passed as a format name.
    """
    def __init__(self):
        Exception.__init__(self, """Invalid format option. Valid options are 'ascii' (default), 'hex', and 'base64'.""")

class InvalidMode(Exception):
    """ Exception raised when an invalid string is
    passed as a cipher operation.
    """
    def __init__(self):
        Exception.__init__(self, """Invalid cipher operation. Valid options are 'encrypt' (default) and 'decrypt'.""")

class InvalidProfile(Exception):
    """ Exception raised when an invalid string is passed 
    as a user token.
    """
    def __init__(self):
        Exception.__init__(self, "Unable to parse profile.")

class InvalidAssumptions(Exception):
    """ Exception raised when some assumptions required by
    a test or attack are likely not valid. """
    def __init__(self):
        Exception.__init__(self, "The assumptions of this method are likely not valid.")

# TODO: test and document
class Unprintable(Exception):
    def __init__(self, ptext):
        Exception.__init__(self, "Unprintable characters in message:\n%s" % repr(ptext))

######### 2. Conversions between byte representations ########

def decode(msg, msg_format='ascii'):
    """ Convert an ascii-, hex-, or base64-encoded
    string into a byte array.

    Args:
        msg (string): a string representing a series
        of bytes in either ascii, hex, or base64 
        encoding.

        msg_format (string): the encoding of the bytes
        represented by 'msg'. Options are 'ascii'
        (default), 'hex', and 'base64'.

    Returns:
        bytearray: a bytearray containing the bytes
        represented by 'msg'. 

    Raises:
        tools.InvalidFormat: if 'msg_format' is nonempty 
        and not equal to 'ascii', 'hex', or 'base64'. 
    """
    if msg_format not in valid_formats:
        raise InvalidFormat
    if msg_format == 'ascii':
        msg_bytes = bytearray(msg)
    elif msg_format == 'hex':
        msg_bytes = bytearray(base64.b16decode(msg, True))
    else:
        msg_bytes = bytearray(base64.b64decode(msg))
    return msg_bytes

def encode(msg_bytes, out_format='ascii'):
    """ Convert a byte array into an ascii-, hex-, or 
    base64-encoded string.

    Args:
        msg_bytes (bytearray): the byte array to be
        converted

        out_format (string): the desired encoding of
        the bytes of 'msg_bytes' in the output string. 
        Options are 'ascii' (default), 'hex', and 
        'base64'.

    Returns:
        string: string representing the bytes of 
        'msg_bytes', with encoding 'out_format'. 
 
    Raises:
        tools.InvalidFormat: if 'msg_format' is nonempty 
        and not equal to 'ascii', 'hex', or 'base64'. 
    """
    if out_format not in valid_formats:
        raise InvalidFormat
    if out_format == 'ascii':
        msg = str(msg_bytes)
    elif out_format == 'hex':
        msg = base64.b16encode(msg_bytes).lower()
    else:
        msg = base64.b64encode(msg_bytes)
    return msg

# TODO: this was written in the following very ugly way due to 
# lack of patience for something better. Rewrite, preferably 
# using encode/decode fns in some way!!
def decToLitEndHex(n, pad_to_bytes=8):
    assert (n >= 0), "Decimal number must be nonnegative"
    big_end = hex(n)[2:]
    if len(big_end) % 2 != 0:
        big_end = '0' + big_end
    pad = '0' * (2 * pad_to_bytes - len(big_end))
    little_end = big_end[-2:]
    for k in range(len(big_end)/2):
        little_end += big_end[-2*(k + 1): -2*k]
    pad_little_end = little_end + pad
    return pad_little_end 

############ 3. Bitwise operations on strings ##############

def XOR(msg1, msg2, in_format1='ascii', in_format2='ascii'):
    """ Compute the bitwise XOR of two strings representing
    equal numbers of bytes, and returns as a bytearray.

    Args:
        msg1 (string): one of the two strings to be XOR'd.
        
        msg2 (string): the other string to be XOR'd.

        in_format1 (string): format in which the bytes
        represented by 'msg1' are encoded. Options are 'ascii'
        (default), 'hex', and 'base64'.

        in_format2 (string): format in which the bytes
        represented by 'msg2' are encoded. Options are 'ascii'
        (default), 'hex', and 'base64'.

    Returns:
        bytearray: byte array containing the bitwise 
        XOR of the bytes represented by 'msg1' and 'msg2'
        respectively.

    Raises:
        AssertionError, "Messages must be of equal length":
        if 'msg1' and 'msg2' do not represent equal numbers
        of bytes after decoding using tools.decode with
        format options 'in_format1' and 'in_format2'
        respectively.
    """
    msg1_bytes = decode(msg1, in_format1)
    msg2_bytes = decode(msg2, in_format2)
    assert (len(msg1_bytes) == len(msg2_bytes)), "Messages must be of equal length"
    xor = bytearray([msg1_bytes[i] ^ msg2_bytes[i] for i in range(len(msg1_bytes))])
    return xor
    
def hamDist(msg1, msg2, in_format1='ascii', in_format2='ascii'):
    """ Compute the Hamming distance between two strings
    representing equal numbers of bytes.

    Args:
        msg1 (string): one of the two strings to be compared.

        msg2 (string): the other string to be compared.

        in_format1 (string): format in which the bytes
        represented by 'msg1' are encoded. Options are 'ascii'
        (default), 'hex', and 'base64'.

        in_format2 (string): format in which the bytes
        represented by 'msg2' are encoded. Options are 'ascii'
        (default), 'hex', and 'base64'.
        
    Returns:
        int: the number of places at which the bit values
        of the byte arrays represented by 'msg1' and 'msg2' 
        (after decoding using tools.decode with format
        options 'in_format1' and 'in_format2' respectively)
        are not equal. Always returns a nonnegative integer. 
    """
    xor_bytes = XOR(msg1, msg2, in_format1, in_format2)
    xor_bits = ''.join(bin(byt)[2:] for byt in xor_bytes)
    dist = sum([int(ch) for ch in xor_bits])
    return dist

# TODO: test and document
def mtNextWord(word, i):
    word_len = 32
    f = 1812433253
    next_word = (f * ( word ^ (word >> (word_len - 2))) + i) & 0xFFFFFFFF
    return next_word

# TODO: test and document
def mtInitialize(word):
    state_words = 624
    state = [word] + [0] * (state_words - 1)
    for i in range(1, state_words):
        state[i] = (mtNextWord(state[i - 1], i))
    return state

# TODO: test and document
def mtTwist(word):
    '''
    Args:
        word: a 32-bit integer

    Returns:
        twist: a 32-bit integer
    '''
    a = int('9908B0DF', 16)
    twist = word >> 1
    if word % 2:
        twist = twist ^ a
    return twist

# TODO: test and document
def mtTemper(word):
    '''
    Args:
        word: a 32-bit integer

    Returns:
        tempered: a 32-bit integer
    '''
    U = 11
    S = 7
    T = 15
    L = 18
    B = int('9D2C5680', 16)
    C = int('EFC60000', 16)
    
    x = word ^ (word >> U)
    y = x ^ ((x << S) & B)
    z = y ^ ((y << T) & C)
    tempered = z ^ (z >> L)
    return tempered

# TODO: test and document
def mtUntemper(tempered):
    '''
    Args:
        tempered: a 32-bit integer, assumed to be the output of mtTemper() on some 32-bit input
    
    Returns:
        word: a 32-bit integer which is the preimage of 'tempered' under mtTemper()
    '''
    U = 11
    S = 7
    T = 15
    L = 18
    B = int('9D2C5680', 16)
    C = int('EFC60000', 16)

    z = tempered ^ (tempered >> L)
    y = z ^ ((z << T) & C) ^ ((z << 2*T) & (C << T) & C)
    x = y ^ ((y << S) & B) ^ ((y << 2*S) & (B << S) & B) ^ ((y << 3*S) & (B << 2*S) & (B << S) & B) ^ ((y << 4*S) & (B << 3*S) & (B << 2*S) & (B << S) & B)
    word = x ^ (x >> U) ^ (x >> 2*U)
    return word

class mt19937():  
    def __init__(self, seed):
        self.state = mtInitialize(seed)
        self.index = 0
    
    def next(self):
        state = self.state
        index = self.index
        new = state[(index + 397) % 624] ^ (mtTwist((state[index] & 0x80000000) ^ (state[(index + 1) % 624] & 0x7fffffff)))
        self.state[index] = new
        self.index = (index + 1) % 624
        return mtTemper(new)

######## 4. Encryption and decryption functions #############

def repXOR(msg, key, msg_format='ascii', key_format='ascii'):
    """ Encrypts a message using the repeating-key XOR cipher.

    That is, computes the bitwise XOR of a message with a key,
    repeating the key as necessary if the key is shorter than
    the message (or truncating the key if it is longer than
    the message). 

    Args:
        msg (string): the message to be encrypted.

        key (string): the key to be used for encryption.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        key_format (string): the format in which the bytes
        of 'key' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.
    
    Returns: 
        bytearray: the bitwise XOR of 'msg' with repetitions of
        'key' as necessary.
    """
    msg_bytes, key_bytes = decode(msg, msg_format), decode(key, key_format)
    assert (len(key_bytes) > 0), "Key must contain at least 1 byte"

    key_remainder = key_bytes[0:(len(msg_bytes) % len(key_bytes))]
    key_rep = key_bytes * (len(msg_bytes)/len(key_bytes)) + key_remainder
    out = XOR(msg_bytes, key_rep, 'ascii', 'ascii')

    return out


def pad(msg, msg_format='ascii', block_size=16, extra=True):
    """ Implement PKCS#7 padding.

    Given a message and a block size, append bytes
    to the message until the resulting string has length 
    equal to a multiple of the block size, as follows.
    If the length of the message is already equal to the
    block size, append one extra block in which each byte 
    is equal to the block size. Otherwise, letting k be the
    difference between the length of the message and the block
    size, append k copies of the byte representing the integer
    k. 

    Optionally (if PKCS#7 padding is not required), avoid 
    adding a block of padding when message length is a multiple
    of the block size.

    Args:
        msg (string): the message to be padded. 

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        block_size (int): the desired length of the padded
        message. Must be in the range [1, 255] inclusive.
        Default value is 16.

        extra (bool): if True (default), then add a block of 
        padding when the length of 'msg' is a multiple of 
        'block_size', not if False. 

    Returns:
        string: the ascii-encoded concatenation of the bytes
        of 'msg' with padding bytes.
    """
    assert (0 < block_size and block_size < 256), "Block size must be an integer in [1, 255] inclusive"
    msg_bytes = decode(msg, msg_format)
    if len(msg_bytes) % block_size == 0:
        if extra == False:
            return str(msg_bytes)
        else: 
            pad_size = block_size
    else:
        steps = (len(msg_bytes)/block_size) + 1
        pad_size = block_size * steps - len(msg_bytes)
    pad_bytes = bytearray([pad_size] * pad_size)
    pad_msg = str(msg_bytes + pad_bytes)
    return pad_msg

def stripPad(msg, block_size=16, strict=True):
    """ Identifies and removes (if any) PKCS#7 padding from a
    string of ascii-encoded bytes. 

    Args:
        msg (string): the message from which to remove padding.

        block_size (int): the block size for the padding 
        scheme. Must be in [1, 255] inclusive. Default value
        is 16.

        strict (bool): if True, raises an exception when
        tail of 'msg' cannot be resolved to valid PKCS#7 
        padding; if False, imply return 'msg'.

    Returns:
        string: the message (as a string of ascii-encoded 
        bytes) after removing padding.

    Raises:
        BadPad: if tail of 'msg' cannot be resolved to valid
        PKCS#7 padding and if 'strict'=True.
    """
    poss_pad_size = ord(msg[-1])
    in_bounds = (poss_pad_size >= 1 and poss_pad_size <= block_size)
    if in_bounds:
        poss_pad = msg[-1 * poss_pad_size:]
    elif strict:
        raise BadPad
    else: 
        return msg

    if (poss_pad == msg[-1] * poss_pad_size):
        strip_msg = msg[:-1 * poss_pad_size]
        return strip_msg
    elif strict:
        raise BadPad
    else:
        return msg

def validatePadAES_CBC(msg, key, iv='', block_size=16):
    """ Given a message, key, and IV, decrypt the 
    message using AES-CBC and check whether the decryption
    has valid PKCS#7 padding.

    Args:
        msg (string): the message to be decrypted and validated.
        
        key (string): the key to be used for decryption.

        iv (string): the initial vector (IV) to be used for
        decryption. Default value is '', in which case
        tools.AES_CBC will interpret the first block of 'msg'
        as the IV.

        block_size (int): the block size of the AES cipher. 
        Default value is 16.

    Returns:
        bool: True if the decryption of 'msg' has valid PKCS#7
        padding, False if not. 
    """
    plaintext = AES_CBC(msg, rand_key, iv, fn='decrypt')
    try:
        stripPad(plaintext, block_size)
        return True
    except BadPad:
        return False        

def blockify(msg, msg_format='ascii', block_size=16, extra=True):
    """ Given a message and a block size, apply PKCS#7 padding
    to the message (see docstring for tools.pad), divide the 
    padded message into blocks, and return a list of the blocks.

    Optionally, avoid adding an extra block of padding in case
    the length of the message is an exact multiple of the block
    size (this is not consistent with PKCS#7 standard but is
    sometimes useful). 

    Args:
        msg (string): the message to be blockified.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        block_size (int): the desired block size for the
        padding scheme. Must be in [1, 255] inclusive. 
        Default value is 16.

        extra (bool): if True, add a full block of padding
        when the length of 'msg' is a multiple of
        'block_size'; not if False. 

    Returns: 
        list of strings: a list of the blocks (each of length
        'block_size') of the padded message.
    """
    assert (1 <= block_size and block_size < 256), "Block size must be an integer in range(1, 256)"

    msg_pad = pad(msg, msg_format, block_size, extra)
    num_blocks = len(msg_pad)/block_size
    blocks = [msg_pad[block_size * i: block_size * (i+1)] for i in range(num_blocks)]
    return blocks

def AES_ECB(msg, key, msg_format='ascii', key_format='ascii', fn='encrypt', extra=True):
    """ Encrypts or decrypts a message under a specified key
    using AES in ECB mode.

    Args:
        msg (string): the message to be en/decrypted.
        
        key (string): the key to be used for en/decryption.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        key_format (string): the format in which the bytes
        of 'key' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        fn (string): the operation which should be performed
        using the cipher. Options are 'encrypt' (default) and
        'decrypt'.
        
        extra (bool): if True, expect that padding scheme
        always adds padding bytes to messages even if the 
        length of the message is a multiple of the block
        size (as PKCS#7 padding requires); if False, expect
        that padding bytes are added only if length of the
        message is not a multiple of the block size. 

    Returns:
        string: the (ascii-encoded) en/decryption of 'msg'
        under 'key' using AES in ECB mode.
    """
    if key_format == 'ascii':
        key_str = key
    else:
        key_str = encode(decode(key, key_format), 'ascii')
    if fn not in valid_fns:
        raise InvalidMode

    cipher = AES.new(key_str, AES.MODE_ECB)
    if fn == 'encrypt':
        blocks = blockify(msg, msg_format, 16, extra)
        out = ''.join(cipher.encrypt(block) for block in blocks)
    else:
        blocks = blockify(msg, msg_format, 16, False)
        decr = ''.join(cipher.decrypt(block) for block in blocks)
        out = stripPad(decr, strict=False)
    return out

def AES_ECBFile(in_filename, key, in_file_format='ascii', key_format='ascii', fn='encrypt', out_filename='', out_file_format='ascii'):
    """ Given a key and the name of a file, encrypt or 
    decrypt the file under the key using AES in ECB mode. 
    Optionally, write the output to a specified file.

    Args:
        in_filename (string): the name of the file to be
        en/decrypted.

        key (string): the key to be used for en/decryption.
        Must consist of 16 bytes.

        in_file_format (string): the format in which the bytes
        of 'in_filename' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

        key_format (string): the format in which the bytes
        of 'key' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

        fn (string): the operation which should be performed
        using the cipher. Options are 'encrypt' (default) and
        'decrypt'.

        out_filename (string): the name of a file to hold the
        output. If empty, output will simply be returned.

        out_file_format (string): the encoding format in case
        output is written to a file. Ignored if 'out_filename'
        is empty.

    Returns:
        (if 'out_filename' == '') string: the ascii-encoded
        de/encryption of 'msg' under 'key'.

        (if 'out_filename' != '') None
    """
    with open(in_filename, 'r') as infile:
        msg = infile.read()
    out = AES_ECB(msg, key, in_file_format, key_format, fn, extra=True)
    if out_filename != '':
        with open(out_filename, 'w') as outfile:
            outfile.write(encode(out, out_file_format))
            return
    else:
        return out

def AES_CBC(msg, key, iv='', msg_format='ascii', key_format='ascii', iv_format='ascii', fn='encrypt'):
    """ Encrypts or decrypts a message under a specified key
    using AES in CBC mode.

    When encrypting, the user should provide an initial value
    (IV), consisting of one block, as the 'iv' argument. The
    IV is used during encryption and then prepended to the
    encrypted message before returning. The IV which was used
    during encryption must also be supplied during decryption.
    When decrypting, the user may either leave the 'iv'
    argument empty, in which case the first block of the 'msg'
    argument is assumed to be the IV, or may provide the IV as
    the 'iv' argument.

    Args:
        msg (string): the message to be en/decrypted.

        key (string): the key to be used for en/decryption.
        Must consist of 16 bytes.

        iv (string): the initial value to be used for
        en/decryption. Must consist of 16 bytes.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        key_format (string): the format in which the bytes
        of 'key' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        iv_format (string): the format in which the bytes
        of 'iv' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

        fn (string): the operation which should be performed
        using the cipher. Options are 'encrypt' (default) and
        'decrypt'.

    Returns:
        string: the en/decryption of 'msg' under 'key' with
        initial vector 'iv' using AES in CBC mode. If the 
        operation 'fn' was 'encrypt', 'iv' is prepended to 
        the encrypted message. If 'fn' was 'decrypt' and 
        'iv' was empty, i.e., if the first block of 'msg'
        was the initial vector, then the IV is stripped 
        from the decrypted message. Padding is not stripped.

    Raises: 
        InvalidMode: if 'fn' is not in 'valid_fns'.
    """
    if fn not in valid_fns:
        raise InvalidMode
    
    key_str = encode(decode(key, key_format), 'ascii')
    assert (len(key_str) == 16), "Key must be 16 bytes long"
    
    iv_str = encode(decode(iv, iv_format), 'ascii')
    if fn == 'encrypt' or iv_str:
        assert (len(iv_str) == 16), "IV must be 16 bytes long"

    in_blocks = blockify(msg, msg_format, block_size=16, extra=False)
    out_blocks = []

    if fn == 'encrypt':
        out_blocks.append(iv_str)
        for k in range(len(in_blocks)):
            out_blocks.append(newBlockAES_CBC(in_blocks[k], out_blocks[k], key_str, fn))
    elif (fn == 'decrypt' and iv_str != ''):
        in_blocks.append(iv_str)
        for k in range(len(in_blocks) - 1):
            out_blocks.append(newBlockAES_CBC(in_blocks[k], in_blocks[k-1], key_str, fn))
    else:
        # assume first block of msg is the iv
        for k in range(1, len(in_blocks)):
            out_blocks.append(newBlockAES_CBC(in_blocks[k], in_blocks[k-1], key_str, fn))

    out = ''.join(block for block in out_blocks)
    return out

def newBlockAES_CBC(block1, block2, key, fn='encrypt'):
    """ Auxiliary function to compute a block of an AES-CBC
    en/decryption.

    For context, see the docstring and source of tools.AES_CBC.
    In the following arg descriptions, assume we are computing
    the k-th block of an AES-CBC en/decryption. 

    Args:
        block1 (string): a string of 16 ascii-encoded bytes.
        If encrypting, this is the (k-1)-th block of the 
        ciphertext (or is the initial vector if k == 0). If 
        decrypting, this is the k-th block of the ciphertext.
        
        block2 (string): a string of 16 ascii-encoded bytes.
        If encrypting, this is the k-th block of the plaintext.
        If decrypting, this is the (k-1)-th block of the 
        ciphertext (or is the initial vector if k == 0).

        key (string): the key used for en/decryption. Must
        consist of 16 ascii-encoded bytes.

        fn (string): the operation which should be performed
        using the cipher. Options are 'encrypt' (default) and
        'decrypt'.

    Returns:
        string: a string of 16 ascii-encoded bytes representing
        one block of an AES-CBC en/decryption. Look at source
        together with a diagram of AES-CBC for specifics.
    """
    if fn == 'encrypt':
        xor_block = str(XOR(block1, block2, 'ascii', 'ascii'))
        new_block = AES_ECB(xor_block, key, 'ascii', 'ascii', fn, False)
    elif fn == 'decrypt':
        decr_block = AES_ECB(block1, key, 'ascii', 'ascii', fn, False)
        new_block = str(XOR(decr_block, block2, 'ascii', 'ascii'))

    return new_block
    
def AES_CBCFile(in_filename, key, iv, in_file_format='ascii', key_format='ascii', iv_format='ascii', fn='encrypt', out_filename='', out_file_format='ascii'):
    """ Given a key, an initial vector, and the name of a
    file, encrypt or decrypt the file under the key using
    AES in CBC mode. Optionally, write the output to a
    specified file.

    Args:
        in_filename (string): the name of the file to be
        en/decrypted.

        key (string): the key to be used for en/decryption.
        Must consist of 16 bytes.

        iv (string): the initial vector to be used for en/
        decryption. If nonempty, must consist of 16 bytes.
        See docstring for tools.AES_CBC for how the 'iv'
        argument is treated.

        in_file_format (string): the format in which the bytes
        of 'in_filename' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

        key_format (string): the format in which the bytes
        of 'key' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

        iv_format (string): the format in which the bytes of 
        'iv' are encoded. Options are 'ascii' (default), 
        'hex', and 'base64'.

        fn (string): the operation which should be performed
        using the cipher. Options are 'encrypt' (default) and
        'decrypt'.

        out_filename (string): the name of a file to hold the
        output. If empty, output will simply be returned.

        out_file_format (string): the encoding format in case
        output is written to a file. Ignored if 'out_filename'
        is empty.

    Returns:
        (if 'out_filename' == '') string: the ascii-encoded
        de/encryption of 'msg' under 'key' with initial 
        vector 'iv'. See tools.AES_CBC for details of how 
        the initial vector is treated. 

        (if 'out_filename' != '') None
    """
    with open(in_filename, 'r') as infile:
        msg = infile.read()
    out = AES_CBC(msg, key, iv, in_file_format, key_format, iv_format, fn)
    if out_filename != '':
        with open(out_filename, 'w') as outfile:
            outfile.write(encode(out, out_file_format))
            return
    else:
        return out

# TODO: test and document
def keyStreamBytesCTR(offset, length, key, nonce='0'*16, msg_format='ascii', key_format='ascii', nonce_format='hex'):
    block_size = 16
    start_block_num = offset / block_size
    end_block_num = (offset + length) / block_size
    start_block_offset = offset % block_size
    keystream = ''

    for block_num in range(start_block_num, end_block_num + 1):
        ctr_str = nonce + decToLitEndHex(block_num)
        ctr_encr = AES_ECB(ctr_str, key, 'hex', key_format, 'encrypt', False)
        keystream += ctr_encr

    keystream_bytes = keystream[start_block_offset:(start_block_offset + length)]
    return keystream_bytes

# TODO: clean up, document
def AES_CTR(msg, key, nonce='0'*16, msg_format='ascii', key_format='ascii', nonce_format='hex'):
    block_size = 16
    msg_str = encode(decode(msg, msg_format), 'ascii')
    keystream = keyStreamBytesCTR(0, len(msg_str), key, nonce, msg_format, key_format, nonce_format)
    ctext = XOR(msg_str, keystream, 'ascii', 'ascii')
    return str(ctext)

# TODO: clean up, document. note that this works for both encryption and decryption
def mt19937_CTR(msg, seed, msg_format='ascii'):
    ctext = ''
    ctr = 0
    twister = mt19937(seed)
    msg_bytes = encode(decode(msg, msg_format), 'ascii')
    
    for byt in msg_bytes:
        # let key be the 8 least significant bits of the next output of twister
        key = (twister.next() & 0xFF)
        ctext += str(XOR(chr(key), byt, 'ascii', 'ascii'))

    return ctext

################### 5. Toy applications ###################

# TODO: it's convenient here to have different return types
# depending on the inputs (i.e. depending on test_mode), but
# it's probably poor design. same comment for several other
# functions in this file. 
def encrOracle(msg, msg_format='ascii', test_mode=False):
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
    pre_bytes = randBytes(random.randint(5, 10))
    post_bytes = randBytes(random.randint(5, 10))
    plaintext = pre_bytes + str(decode(msg, msg_format)) + post_bytes
    key = randBytes(16)
    coin = random.randint(0, 1)

    if coin:
        if test_mode: 
            return [True, AES_ECB(plaintext, key)]
        else:
            return AES_ECB(plaintext, key)
    else:
        iv = randBytes(16)
        if test_mode:
            return (False, AES_CBC(plaintext, key, iv))
        else:
            return AES_CBC(plaintext, key, iv)

def ECBOracle(msg, msg_format='ascii'):
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
    plaintext = str(decode(msg, msg_format) + decode(postfix, 'base64'))
    ciphertext = AES_ECB(plaintext, rand_key)
    return ciphertext

def ECBOraclePlus(msg, msg_format='ascii'):
    """ Prepends a fixed random string to a message and
    then calls tools.ECBOracle. 

    Args:
        msg (string): the message to be affixed-to and 
        encrypted.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

    Returns:
        string: The ascii-encoded encryption of the
        concatenation of 'msg' with the bytes of
        tools.rand_prefix (as prefix) and of 
        tools.postfix1 (as postfix), using AES-ECB under 
        a fixed random 16-byte key.
    """
    return ECBOracle(rand_prefix + decode(msg, msg_format), 'ascii')

def CBCOracle():
    """ Chooses one of the 10 strings in tools.set3ch17_ctexts
    at random, and encrypts it using AES-CBC with key
    tools.rand_key and a random one-time 16-byte IV. 
    
    Returns:
        string: the AES-CBC encryption of a random string
        from the list tools.set3ch17_ctexts.
    """
    ind = random.randint(0, 9)
    ctext = set3ch17_ctexts[ind]
    iv = randBytes(16)
    return AES_CBC(ctext, rand_key, iv, msg_format='base64')

def quoteChars(msg, char_list):
    """ Given a message and a list of characters, adds quotes
    around all occurances of those characters in the message.

    Args: 
        msg (string): the message to be modified.

        char_list (list of chars): a list of all characters
        to be quoted out in 'msg'.

    Returns:
        string: the modification of 'msg' which has quotes
        around every character in 'char_list'.
    """
    msg_clean = msg
    for letter in char_list:
        msg_clean = msg_clean.replace(letter, "\'" + letter + "\'")
    return msg_clean

def parseProfile(msg, sep_field='&', sep_key='='):
    """ Parses a structured token into a dictionary.

    Args:
        msg (string): a structured token in which some
        consistent character separates each field from
        the next, and another character separates each
        key from its value.

        sep_field (char): the character which denotes
        the beginning of a new field according to the
        format of the token 'msg'.

        sep_key (char): the character which denotes 
        the separation between a key and a value 
        according to the format of the token 'msg'.

    Returns:
        dict (string: string): a dictionary of the keys
        and values represented by the token 'msg'.

    Raises:
        InvalidProfile: if 'msg' is not a well-formed 
        token.
    """
    try:
        fields = [substr.split(sep_key) for substr in msg.split(sep_field)]
        tags = { field[0]: field[1] for field in fields }
    except IndexError:
        raise InvalidProfile
        return
    return tags 

def newProfile(email_addr):
    """ Given an email address, generates a random user ID 
    number in range [1, 1000] and creates a token with 
    user privilege. 

    Args:
        email_addr (string): the email address to be used in
        the token.
    
    Returns:
        string: a token of form
            "email='email_addr'&uid=UID&role=user" 
        after quoting out active chars '&' and '=' from
        'email_addr'.
    """
    email_clean = quoteChars(email_addr, ['&', '='])
    uid = str(random.randint(1, 1000))
    role = 'user'
    profile = '&'.join(['email='+email_clean, 'uid='+uid, 'role='+role])

    return profile 

def newEncrProfile(email_addr):
    """ Creates a new user profile with tools.newProfile
    and encrypts it using AES-ECB under a fixed random
    key.

    Args:
        email_addr (string): the email address to be used
        to create the profile.

    Returns:
        string: the encryption of a profile created using
        tools.newProfile using AES_ECB with the fixed
        random key 'rand_key'. 
    """
    profile = newProfile(email_addr)
    return AES_ECB(profile, rand_key)

def validateProfileECB(ciphertext, verbose=False):
    """ Given a string, attempts to decrypt the string 
    using AES-ECB and the key 'rand_key' and then to 
    parse the result as a profile of form
        'email=EMAIL&uid=UID&role=ROLE'.

    Args:
        ciphertext (string): the message to be tested for
        the property of being an encrypted profile.

        verbose (bool): if True, print a message with 
        login email, UID, and role upon successful parsing
        of the decryption of 'ciphertext'; silence if False.

    Returns:
        dict (string: string): if decryption of 'ciphertext'
        is successfully parsed, return a dictionary of keys
        and values represented by the decrypted token. 
    """
    plaintext = AES_ECB(ciphertext, key=rand_key, fn='decrypt')
    parsed_profile = parseProfile(plaintext)
    if verbose==True:
        print "You are logged in as %s with email address %s and UID %s" % (parsed_profile['role'], parsed_profile['email'], parsed_profile['uid'])
    return parsed_profile

def newAuthStringCBC(msg, msg_format='ascii'):
    """ Given a string, concatenates it with the prefix 
    tools.auth_prefix and the postfix tools.auth_postfix
    and then encrypts the result with AES-CBC under the key
    tools.rand_key and an all-zero IV.

    Before encryption, the auth string is

"comment1=cooking%20MCs;userdata=MSG;comment2=%20like%20a%20pound%20of%20bacon"
    
    where MSG is the (ascii encoding of) the user input.

    Args: 
        msg (string): the user input to the auth string.

        msg_format (string): msg_format (string): the format
        in which the bytes of 'msg' are encoded. Options are
        'ascii' (default), 'hex', and 'base64'.

    Returns:
        string: the encrypted auth string.
    """
    if msg_format != 'ascii':
        msg_str = encode(decode(msg, msg_format), 'ascii')
    else:
        msg_str = msg
    msg_clean = quoteChars(msg_str, [';', '='])
    affix = auth_prefix + msg_clean + auth_postfix
    iv = '\x00' * 16
    ciphertext = AES_CBC(affix, rand_key, iv)
    return ciphertext

def newAuthStringCTR(msg, msg_format='ascii'):
    """ Given a string, concatenates it with the prefix 
    tools.auth_prefix and the postfix tools.auth_postfix
    and then encrypts the result with AES-CTR under the key
    tools.rand_key and an all-0 nonce. 

    Before encryption, the auth string is

"comment1=cooking%20MCs;userdata=MSG;comment2=%20like%20a%20pound%20of%20bacon"
    
    where MSG is the (ascii encoding of) the user input.

    Args: 
        msg (string): the user input to the auth string.

        msg_format (string): msg_format (string): the format
        in which the bytes of 'msg' are encoded. Options are
        'ascii' (default), 'hex', and 'base64'.

    Returns:
        string: the encrypted auth string.
    """
    if msg_format != 'ascii':
        msg_str = encode(decode(msg, msg_format), 'ascii')
    else:
        msg_str = msg
    msg_clean = quoteChars(msg_str, [';', '='])
    affix = auth_prefix + msg_clean + auth_postfix
    iv = '\x00' * 16
    ciphertext = AES_CTR(affix, rand_key)
    return ciphertext

# TODO: should i generate a random nonce for each encryption?
def validateAuthStringCBC(msg):
    """ Given a string, decrypt it with AES-CBC using the key
    tools.rand_key and attempt to parse the result as a token
    of the form produced by tools.newAuthString; validate
    if the decryption parses to an admin token.

    Args:
        msg (string): a string to be validated/rejected as
        an encrypted admin token.

    Returns:
        string: Returns True if parsing is successful and
        'admin' appears in the resulting list of keys; returns
        False otherwise. 
    """
    plaintext = AES_CBC(msg, rand_key, fn='decrypt')
    try:
        tags = parseProfile(plaintext, ';')
        if 'admin' in tags.keys():
            return True
        else:
            return False
    except IndexError:
        return False

def validateAuthStringCTR(msg):
    """ Given a string, decrypt it with AES-CTR using the key
    tools.rand_key and attempt to parse the result as a token
    of the form produced by tools.newAuthStringCTR; validate
    if the decryption parses to an admin token.

    Args:
        msg (string): a string to be validated/rejected as
        an encrypted admin token.

    Returns:
        string: Returns True if parsing is successful and
        'admin' appears in the resulting list of keys; returns
        False otherwise. 
    """
    plaintext = AES_CTR(msg, rand_key)
    try:
        tags = parseProfile(plaintext, ';')
        if 'admin' in tags.keys():
            return True
        else:
            return False
    except IndexError:
        return False

# TODO: document
def mtGenerator():
    time.sleep(random.randint(40, 1000))
    timestamp = int(time.time())
    twister = mt19937(timestamp)
    time.sleep(random.randint(40, 1000))
    return twister.next()

# TODO: document
def mt19937_CTR_Oracle(msg, msg_format='ascii'):
    seed = random.randint(0, 2**16)
    prefix_length = random.randint(0, 20)
    prefix = randBytes(prefix_length)
    msg_bytes = encode(decode(msg, msg_format), 'ascii')
    ptext = prefix + msg_bytes
    return mt19937_CTR(ptext, seed, msg_format)

# TODO: document
def mtPasswordReset(userid):
    seed = (int(time.time()) & 0xFFFF)
    prefix_length = random.randint(0, 20)
    prefix = randBytes(prefix_length)
    ptext = prefix + userid
    return mt19937_CTR(ptext, seed, 'ascii')

def readBytesCTR(ctext, offset, length, key, nonce='0'*16, ctext_format='ascii', key_format='ascii', nonce_format='hex'):
    assert (offset >= 0), "Offset must be nonnegative"
    assert (length > 0), "Length must be positive"
    ctext_bytes = encode(decode(ctext, ctext_format), 'ascii')
    assert (offset + length <= len(ctext_bytes)), "Request out of range"
    keystream_bytes = keyStreamBytesCTR(offset, length, key, nonce, ctext_format, key_format, nonce_format)
    decrypt = XOR(ctext[offset:(offset+length)], keystream_bytes, 'ascii', 'ascii')
    return decrypt

def editBytesCTR(ctext, offset, newtext, key, nonce='0'*16, ctext_format='ascii', newtext_format='ascii', key_format='ascii', nonce_format='ascii'):
    assert (offset >= 0), "Offset must be nonnegative"
    newtext_bytes = encode(decode(newtext, newtext_format), 'ascii')
    length = len(newtext)
    assert (length > 0), "Length must be positive"
    ctext_bytes = encode(decode(ctext, ctext_format), 'ascii')
    assert (offset + length <= len(ctext_bytes)), "Request out of range"
    keystream_bytes = keyStreamBytesCTR(offset, length, key, nonce, ctext_format, key_format, nonce_format)
    ctext_patch = XOR(newtext_bytes, keystream_bytes, 'ascii', 'ascii')
    new_ctext = ctext[:offset] + ctext_patch + ctext[offset+length:]
    return new_ctext

# an API for users to request edited encryptions of a particular ciphertext
def editAPI_CTR(ctext, offset, newtext, ctext_format='ascii', newtext_format='ascii'):
    edit = editBytesCTR(ctext, offset, newtext, rand_key)
    return edit

# TODO: test and document
def AES_CBC_IVkey(msg, key, msg_format='ascii', key_format='ascii', fn='encrypt'):
    if fn == 'encrypt':
        return AES_CBC(msg, key, key, msg_format, key_format, key_format, 'encrypt')[16:]
    elif fn == 'decrypt':
        return AES_CBC(msg, key, key, msg_format, key_format, key_format, 'decrypt')
    
# TODO: test and document
def verifyAsciiCBC(msg, key):
    ptext = AES_CBC_IVkey(msg, key, 'ascii', 'ascii', 'decrypt')
    for char in ptext:
        if (ord(char) > 126):
            raise Unprintable(ptext)
    return True

############# 6. Tools for breaking stuff ##################
# i.   Frequency analysis tools                            #
# ii.  Attacks on AES-ECB                                  #
# iii. Attacks on AES-CBC                                  #
# iv.  Attacks on mt19937                                  #
############################################################

############## 6.i Frequency analysis tools ################

def scoreText(msg, case=False, space=True):
    """ Given a string, compute a score representing the
    likelihood that the string is English text. Scores are
    floats in range [-1, 1]. A higher score indicates a
    a higher likelihood that input string was English text.
    By default, the function gives higher scores to strings
    with English-like frequency of spaces, and is not case
    sensitive. Both of these defaults can be changed with
    keyword arguments.

    Algorithm: 
        One point is deducted for each character in the 
        string which is not alphabetic or a space. Points
        are awarded for each character which appears both
        among the 6 most frequent characters in the input
        string and also among the 6 most frequent characters
        in typical English, and likewise for the 6 least 
        frequent characters. The number of points awarded 
        for each such character is equal to the length of 
        the string divided by 12 (as a float). Finally, 
        scores are normalized by the length of the string,
        so scores lie in the range [-1, 1]. 
    
    Heuristics:
        Short texts which are not even close to English 
        (e.g., repeating XOR of an English sentence with a
        random key) generally to have negative scores,
        while the positive range seems to disambiguate well
        between short texts which are "almost English" (e.g.,
        the decryption of repeating-key XOR encryptions with 
        a key which differs in a few characters from the true
        key) and perfect English. The optional keyword
        arguments don't seem to make a big difference in
        outcomes, but are occasionally useful for fine-tuning
        once it's clear what kind of text (spaced,
        case-differentiated, etc) we're looking for. 

    Caveats:
        Since the score only depends on character frequency,
        permuting a text doesn't change the score at all,
        and a random sample from an English text (however 
        unlike English it looks) should score about as well
        as the full text. (We'll use this fact to our advantage
        in cryptopals challenge 6!) 

        May not behave as expected on English texts with an
        unusual amount of punctuation, special characters, 
        or whitespace. Probably doesn't differentiate well
        between English and related human languages. 
    
    Args:
        msg (string): the string which is to be scored.
        
        case (boolean): True if priority should be given
        to case-differentiated English text, False to ignore
        case when scoring.

        space (boolean): True if priority should be given
        to text with a frequency of space characters similar
        to that of typical English, False to ignore spaces when
        scoring. 

    Returns:
        float: a score in the range [-1, 1] (including
        endpoints).
    """
    msg_len, score = 0, 0
    str_counts = {}
    for char in ' .,;?!-':
        str_counts[char] = 0
    for i in range(ord('a'), ord('z') + 1) + range(ord('A'), ord('Z') + 1):
        str_counts[chr(i)] = 0
    # count alpha chars and spaces
    # decrement score for each nonalpha/space char
    for char in msg:
        msg_len += 1
        if char.isalpha() or char in ' .,;?!-':
            str_counts[char] += 1
        else:
            score -= 1
    sort_counts = sorted(str_counts, key=str_counts.get, reverse=True)
    # compare 6 highest- and lowest-freq chars in msg to 
    # those in typical english, and increment score for 
    # each char in common in high/low freq bins
    if case:
        most_freq = set(sort_counts[0:6])
        least_freq = set(sort_counts[-6:])
    else: 
        most_freq = set([char.lower() for char in sort_counts[0:6]])
        least_freq = set([char.lower() for char in sort_counts[-6:]])

    most_freq_en = set('etoai')
    if space:
        most_freq_en.add(' ')
    else:
        most_freq_en.add('n')
    least_freq_en = set('zqxjkv')
    
    pts_per_char = msg_len/float(12)
    score += pts_per_char * (len(most_freq & most_freq_en) + len(least_freq & least_freq_en))
    
    norm_score = score/float(msg_len)
    return norm_score


def scanKeys(msg, msg_format='ascii', case=True, space=True,  verbose=False):
    """ Scans for the key used to encrypt an English text
    using a single-character XOR cipher. 

    Algorithm:
        Given a string, scans through all ascii characters. For each such 
        character, uses tools.repXOR to compute the XOR 
        of the input string with the key consisting of 
        the character times the length of the input string,
        and scores the result using tools.scoreText.
        Returns a tuple containing the highest observed score
        and the corresponding key and decryption. 

    Args:
        msg (string): a string which is to be tested for 
        the property of being a single-character XOR encryption
        of an English text. 

        msg_format (string): the encoding of the bytes 
        represented by the string 'msg'. Options are 'ascii'
        (default), 'hex', and 'base64'.

        case (boolean): see docstring for tools.scoreText.
        
        space (boolean): see docstring for tools.scoreText.
        
        verbose (boolean): if True, function will print the
        highest-scoring key and decryption; not if False.

    Returns:
        tuple (float, int, string): the first parameter is the
        highest observed score, and the second parameter is  
        the key (as an ascii value in range [32, 127]
        inclusive) which produces a decryption achieving that
        high score. The third parameter is that decryption. 

        Note that only one such tuple is returned, even if
        several keys produce decryptions which achieve the
        highest observed score. (In this case, the tuple
        returned will be the one which comes first in
        alphabetical order.)
    """
    key_data = { }
    for key in range(256):
        decrypt_bytes = repXOR(msg, chr(key), msg_format, key_format='ascii')
        decryption = encode(decrypt_bytes, 'ascii')
        key_data[key] = scoreText(decryption, case, space), decryption
    
    sort_scores = sorted(key_data, key=key_data.get, reverse=True)
    best_key = sort_scores[0]
    best_score, best_decryption = key_data[best_key]

    if verbose:
         print "The best result is:\n\n\tKey: %c\n\tDecryption: %s\n\tScore: %s\n" % (best_key, best_decryption, best_score)

    return best_score, best_key, best_decryption

def scanKeysFile(filename, file_format='ascii', verbose=False):
    """ Runs tools.scanKeys on a file which is assumed to 
    contain newline-separated lines, one of which is the 
    encryption using single-character XOR of an English text.
    The best key(s) found by scanKeys for each line are
    stored, and the key(s) which belong to the highest-scoring
    (key, line) pairs overall are returned. The
    highest-scoring (key, line, decryption) tuple is
    optionally printed. 

    Args:
        filename (string): the name of the file to scan.
        The file should contain newline-separated strings.

        file_format (string): encoding of the bytes of
        'filename'. Options are 'ascii' (default), 'hex', and
        'base64'.

        verbose (boolean): if True then highest-scoring key,
        line, and decryption are printed; not if False.

    Returns:
        list (ints): a list of all keys which produce 
        decryptions achieving the highest observed score,
        according to tools.scoreText, when used to decrypt
        some line of the input file. 
    """
    best_lines = []
    best_score = 0
    line_num = 0
    
    with open(filename, 'r') as infile:
        for raw_line in infile:
            line = raw_line.rstrip('\n')
            line_best_score, line_best_key = scanKeys(line, file_format)[:2]

            if line_best_score > best_score:
                best_score = line_best_score
                best_lines = [[line_num, line_best_key, line]]
            elif line_best_score == best_score:
                best_lines.append((line_num, line_best_key, line))
            line_num += 1
    
    if verbose: 
        print "\nThe best result is:\n"
        for candidate in best_lines:
            line_num, key, line = candidate
            decryption = repXOR(line, chr(key), file_format, 'ascii')
            print "\tLine number: %d\n\tLine: %s\n\tKey: %c\n\tDecryption: %s" % (line_num, line, key, decryption)

    best_keys = [candidate[1] for candidate in best_lines]
    return best_keys

def guessKeySize(msg, msg_format='ascii', lower=2, upper=41, segments=4, guesses=1, verbose=False):
    """ Given a string and assuming that the string is the 
    encryption of an English text with repeating-key XOR, 
    guess the length of the key. User can specify the range 
    key lengths to test, and the number of guesses to return
    (in order of likelihood).

    Algorithm:
        The algorithm is based on the observation that, on
        average, pairs of strings of English text have a 
        smaller Hamming distance than pairs of random strings.
        Furthermore, XOR'ing both members of a pair of strings
        with the same key preserves their Hamming distance.
        
        Given a possible key length, slice out a small 
        number of segments of that length. The number of 
        segments is specified by the user (with a tradeoff of 
        time vs. accuracy), and the default number is 4. The 
        average Hamming distance of all of the distinct pairs
        of these segments is computed. This computation is 
        repeated for all key lengths within the bounds 
        specified by the user. The key length which produces 
        the smallest average Hamming distance is returned as
        the most likely key length.
        
    Args:
        msg (string): a string which we assume is the
        encryption of an English text with repeating-key
        XOR.

        msg_format (string): the encoding of the bytes
        represented by 'msg'. Options are 'ascii' (default),
        'hex', and 'base64'.

        lower (int): lower bound (inclusive) on the range of
        possible key sizes. Must be at least 1.

        upper (int): upper bound (exclusive) on the range of
        possible key sizes. Must be greater than 'lower'.

        segments (int): the number of segments for which the 
        Hamming distance is compared.

        guesses (int): the number of guesses to return, in
        decreasing order of likelihood. Must be a positive 
        integer less than or equal to ('upper' - 'lower').

        verbose (boolean): if True then a description of the
        output is printed before returning; not if False.

    Returns:
        list of ints: a list, of length is equal to 'guesses',
        of the most likely keys, in decreasing order of
        likelihood. Each key is an integer in range [32, 127]
        inclusive. 
    """
    assert (lower > 0 and upper > lower), "Please enter a valid range of key sizes"
    assert (segments > 1), "Must use at least 2 segments"
    assert (guesses > 0 and upper - lower >= guesses), "Please enter a valid number of guesses"

    msg_bytes = decode(msg, msg_format)
    assert (len(msg_bytes) >= segments * upper), "The message is too short to support this search range and number of segments"
    
    key_dists = { }
    for i in range(lower, upper):
        key_size = i
        segs = [msg_bytes[j * key_size : (j + 1) * key_size] for j in range(segments)]
        # form the set of pairs of distinct integers 
        # (unordered) in range [0, segments)
        combos = [(j, k) for j in range(segments) for k in range(j)]
        # compute the normalized hamming distance for each pair
        norm_dists = [hamDist(segs[cb[0]], segs[cb[1]]) / float(key_size) for cb in combos]
        # take the average distance of the pairs
        avg_norm_dist = sum(norm_dists) / float(len(combos))
        key_dists[key_size] = avg_norm_dist

    sort_sizes = sorted(key_dists, key=key_dists.get)
    guess_list = sort_sizes[:guesses]

    if verbose:
        if guesses == 1:
            print "The most likely key length is %d.\n" % guess_list[0]
        else:
            print "In order of likelihood, the %d most likely key lengths are:" % guesses
            print ', '.join(map(str, guess_list)) + '\n'
    
    return guess_list

def guessRepXORKey(msg, key_size, msg_format='base64', case=True, space=True, verbose=False):
    """ Given a string which is assumed to be the encryption 
    of an English text using a repeating-key XOR cipher, and
    given the length of the key, this function guesses the
    most likely key.
    
    Algorithm:
        For each index i less than the length m of the key, 
        the (n * m + i)-th bytes of the input string (where
        n runs over the positive integers until the string is
        exhausted) are collected into a new string. The i-th 
        new string consists of all the bytes of the original
        string which were encrypted by XOR'ing with the i-th
        byte of the repeating key. Each of the m new  strings
        is now treated as a single-character-XOR decryption
        problem, which is solved by calling tools.scanKeys.
        The resulting m single-character keys are then pieced
        together to form the repeating key. 

    Args:
        msg (string): the string which is to be decrypted.
        
        key_size (int): the length of the repeating key.

        msg_format (string): the format in which the bytes
        represented by 'msg' are encoded. Options are 'ascii'
        (default), 'hex', and 'base64'.

        case (boolean): see the docstring for tools.scoreText.

        space (boolean): see the docstring for tools.scoreText.

        verbose (boolean): prints decryption of 'msg' with most
        likely key before returning if True, not if False
        (default).

    Returns:
        string: the repeating-XOR key of length 'key_size'
        which was most likely used to encrypt the input string.
    """
    msg_bytes = decode(msg, msg_format)
    indices = [[i for i in range(len(msg_bytes)) if i % key_size == j] for j in range(key_size)]

    blocks = [bytearray(msg_bytes[i] for i in indices[j]) for j in range(key_size)]

    key_chars = [chr(scanKeys(blocks[j], 'ascii', case, space)[1]) for j in range(key_size)]
    key = ''.join(key_chars)

    if verbose:
        print "The best key of length %d is: %s\n" % (key_size, repr(key))
        print "The decryption of the message with this key is:\n"
        print repXOR(msg_bytes, key)
        
    return key

def breakRepXOR(filename, file_format='ascii', case=True, space=True, lower=2, upper=41, segments=4, guesses=1, verbose=False):
    """ Given the name of a file and assuming that the file was
    encrypted using repeating-key XOR, return a list of the 
    most likely keys (in descending order of likelihood). The
    length of the list is specified by the user.

    Algorithm:
        Use tools.guessKeySize to make a list, of the user-
        specified length, of the most likely key sizes in 
        descending order of likelihood. For each of these 
        possible key sizes, use tools.guessRepXORKey to find
        the single most likely key of that size. Return the
        resulting list of keys.

    Args:
        filename (string): the name of a file. The file is 
        assumed to represent the encryption of an English
        text using repeating-key XOR. 

        file_format (string): the format in which the bytes
        of 'filename' are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

        case (boolean): see the docstring for tools.scoreText.
    
        space (boolean): see the docstring for tools.scoreText.

        lower (int): see the docstring for tools.guessKeySize.

        upper (int): see the docstring for tools.guessKeySize.

        segments (int): see the docstring for
        tools.guessKeySize.

        guesses (int): see the docstring for
        tools.guessKeySize.

        verbose (boolean): prints the most likely key sizes 
        and corresponding decryptions before returning if 
        True; not if False. 

    Returns:
        list of ints: a list of the most likely keys, in 
        descending order of likelihood. The length of the list
        is equal to the arg 'guesses'.
    """
    with open(filename, 'r') as infile:
        msg_enc = infile.read()
    keysize_list = guessKeySize(msg_enc, file_format, lower, upper, segments, guesses, verbose)
    key_list = [guessRepXORKey(msg_enc, size, file_format, case, space, verbose) for size in keysize_list]
    return key_list

############### 6.ii. Attacks on AES-ECB #################

def isAES_ECB(msg, msg_format='ascii'):
    """ Determines whether an input string contains a repeated
    block of 16 bytes, which begins at a multiple of 16 bytes.
    
    This is a proxy for determining whether the input string 
    was produced by encryption with AES in ECB mode, since 
    ECB mode is a deterministic cipher which operates on
    16-byte blocks independent of any other information.

    A string with a repeated 16-byte block is not necessarily
    an encryption using AES-ECB (it may be unencrypted, or 
    encrypted with another cipher). Conversely, an AES-ECB
    encryption will not necessarily contain a repeated 16-byte
    block; it will do so if and only if the plaintext contains
    a repeated block. However, this function is an effective 
    proxy for our purposes. 

    Args:
        msg (string): a string which is to be tested for 
        repeated blocks; or, by proxy, for having been produced
        by encryption with AES-ECB.

        msg_format (string): the format in which the bytes
        of 'msg' are encoded. Options are 'ascii'         
        (default), 'hex', and 'base64'.

    Returns:
        boolean: True if 'msg' contains a repeated block of 16 
        bytes, False if not.
    """
    msg_str = decode(msg, msg_format)
    blocks = blockify(msg_str, block_size=16)
    indices = [(i, j) for i in range(len(blocks)) for j in range(i)]
    for (i, j) in indices:
        if blocks[i] == blocks[j]:
            return True
    return False

def isAES_ECBFile(filename, file_format='base64', verbose=False):
    """ Given the name of a file and assuming that the file 
    contains newline-separated strings, returns a list of 
    lines of the file which are likely to have been produced
    by encryption with AES in ECB mode as determined by 
    tools.isAES_ECB.

    Args:
        filename (string): the name of a file containing 
        newline-separated strings.
        
        file_format (string): the format in which the bytes
        of filename are encoded. Options are 'ascii'     
        (default), 'hex', and 'base64'.

        verbose (boolean): prints out the suspicious line 
        numbers before returning if True; not if False.

    Returns:
        list of ints: list of all lines of filename for
        which tools.isAES_ECB returns True.
    """
    with open(filename, 'r') as infile:
        enc_lines = [line.strip('\n') for line in infile.readlines()]

    suspects = []
    for k in range(len(enc_lines)):
        if isAES_ECB(enc_lines[k], file_format):
            suspects.append(k)

    if verbose:
        print "The following line(s) may have been encrypted with AES-ECB:" 
        print ', '.join(map(str, suspects)) + '\n'
    
    return suspects

def isUsingAES_ECB(function, block_size=16, test_mode=False, verbose=False):
    """ Given an unknown encryption function and a block size,
    checks for an indicator that the function is a
    deterministic block cipher with blocks of that size. 

    The indicator is the appearance of repeated blocks of 
    the specified block size in the ciphertext, when repeated
    blocks of that size are supplied to the encryption
    function.

    If the unknown function is actually an oracle with a 
    "test mode" that reveals which cipher it is using, 
    isUsingAES_ECB may also be used in test mode to check 
    its own predictions against the oracle's disclosure. 

    Algorithm: 
        Our model of the unknown encryption function is that
        it possibly appends some prefix and suffix to the 
        messages we supply, and then encrypts them with 
        either AES-ECB or AES-CBC under some unknown key. 
        We guess a block size for the cipher (e.g., 
        the default block size of 16 bytes) and supply the 
        function with a string of identical characters of 
        length 3 times the block size. If our model is
        accurate and if we have guessed the block size of the
        cipher correctly, then (no matter how long the prefix
        is), we're guaranteed to see a repeated block in the
        ciphertext if the cipher is AES-ECB, and very unlikely
        to see a repeated block if the cipher is AES-CBC. 

    Caveat: 
        Although the name of the function is isUsingAES_ECB,
        the test does not actually distinguish the use of 
        AES-ECB from that of any other block cipher in which
        the encryption of each block depends only on the key
        and the corresponding block of the plaintext.

    Args:
        function (function string -> string if 
        'test_mode'==False; function string -> (bool, string)
        if 'test_mode'==True): the encryption
        function to be tested.

        block_size (int): the block size to be tested. Must
        be in range [1, 255] inclusive. Default value is 16.

        test_mode (bool): if True, expects 'function' to return
        a tuple (bool, string), where the first arg of the 
        tuple is True if 'function' is using AES-ECB and False
        otherwise; checks prediction against that arg. If
        False, expects 'function' to return a string and does
        not check accuracy of prediction.

        verbose (bool): ignored if 'test_mode'==False. If 
        'test_mode'==True and 'verbose'==True, prints some
        information about the accuracy of prediction; silent
        if 'verbose'==False.

    Returns:
        (if 'test_mode'==False) bool: True if the output of
        'function' contains a repeated block when our string 
        of 3 * 'block_size' repeated characters is given as 
        input, False if not.

        (if 'test_mode'==True) bool: True if the bool described
        in the 'test_mode'==False case agrees with the bool
        revealed by 'function' running in test mode, False
        if not.
    """
    assert (1 <= block_size and block_size < 256), "\'block_size\' must be an int in [1, 255] inclusive"

    if test_mode:
        witness = function('\x00'*3*block_size, 'ascii', True)
        is_ecb, ciphertext = witness
        diagnosis = isAES_ECB(ciphertext)
        correct = True ^ is_ecb ^ diagnosis
        
        if verbose:
            print "Really using AES-ECB? ", is_ecb
            print "Diagnosed as using AES-ECB? ", diagnosis
            print "---> Correct prediction? ", correct
        return correct
    else:
        witness = function('\x00'*3*block_size, 'ascii')
        return isAES_ECB(witness)

def test_isUsingAES_ECB(function, block_size=16, trials=1, verbose=True):
    """ Runs a specified number of trials of
    tools.isUsingAES_ECB in test mode and reports statistics.

    See the docstring for tools.isUsingAES_ECB for more 
    information about test modes.

    Args:
        function (function: string -> (bool, string)): an 
        encryption function running in a "test mode" (cf.
        tools.encrOracle) which returns a tuple containing
        an encryption of its input together with a bool
        which is True if AES-ECB was used for encryption and
        False otherwise.

        block_size (int): the block size to be tested. Must
        be in [1, 255] inclusive. Default value is 16.

        trials (int): the number of trials to run. Must be a 
        positive integer.

        verbose (bool): if True, print a message with the 
        percentage of successful trials before returning.

    Returns:
        float: the percentage of successful trials.
    """
    assert (trials >= 1), "Number of trials must be a positive integer"
    if verbose:
        print "Running %d trial(s) of isUsingAES_ECB on %s with block size %d...\n" % (trials, function.__name__, block_size)
    fails = 0
    for k in range(trials):
        trial = isUsingAES_ECB(encrOracle, block_size, test_mode=True, verbose=False)
        if not trial:
            fails += 1
    win_rate = (trials - fails)/float(trials) * 100
    if verbose: 
        print "The percentage of successful guesses over %d trials was: %f" % (trials, win_rate)
    return win_rate
    
def findBlockSize(function, upper_bound=256):
    """ Given a function and assuming that it pads its input
    with some prefix and suffix and then applies a block
    cipher such that each block of the ciphertext depends only
    on the key and the corresponding block of the plaintext
    (for example, AES-ECB), find the block size of the cipher.

    Algorithm: 
        If the above description is true of a function, then
        the length of its output grows in discrete steps
        with the size of each step equal to the block size. 
        So we compute the length of the function's output on
        empty input, and then feed the function increasingly
        long messages until the length of the output jumps.
        The difference between the new output length and the
        length on empty input is the block size.

    Args:
        function (function: string -> string): the function
        whose block size is to be determined.

        upper_bound (int): the upper bound on the range of 
        possible block sizes to check. Must be an integer in
        [1, 256] inclusive.

    Returns:
        int: the likely block size of the cipher (a positive
        integer in range [1, 'upper_bound'-1]).

    Raises:
        InvalidAssumptions: in case the output length does
        not jump before 'upper_bound' is reached. 
    """
    assert (0 < upper_bound and upper_bound <= 256), "upper_bound must be an integer in range [1, 256] inclusive."

    init_length = len(function(''))
    block_size = 0
    for k in range(upper_bound):
        test_len = len(function('\x00' * k))
        if test_len > init_length:
            block_size = test_len - init_length
            return block_size
    raise InvalidAssumptions

def prefixBlocks(function, block_size=16):
    """ Given a function and assuming that it concatenates its
    input with a prefix (and possibly suffix) and then applies
    a block cipher such that each block of the ciphertext 
    depends only on the key and the corresponding block of
    the plaintext (e.g., AES-ECB), and given the block size
    of the cipher, find the number of blocks which consist
    exclusively of prefix bytes. 

    Algorithm:
        We first compute the output of the function on two 
        different one-byte inputs: say, '\x00' and '\x01'.
        If the prefix fully occupies the first m blocks of
        the input to the block cipher, then the first m
        blocks of the two outputs will agree. If in addition
        the (m+1)st block is not fully occupied by the prefix,
        then the (m+1)st blocks of the two outputs will 
        disagree. Therefore, the number of blocks fully 
        occupied by the prefix is the number of blocks before
        the first disagreement in the two outputs.

    Args:
        function (function: string -> string): a function which
        is assumed to be of the form described above.

        block_size (int): the block size of the cipher assumed
        to be used by 'cipher'. Must be in [1, 255] inclusive.
        Default value is 16. 

    Returns:
        int: the number of complete blocks occupied by the 
        prefix. 

    Raises:
        InvalidAssumptions: if the lengths of the two test 
        vectors are unequal, or if their length is not a 
        multiple of 'block_length'.
    """
    vec0 = function('\x00')
    vec1 = function('\x01')

    assert (0 < block_size and block_size < 256), "\'block_size\' must be an integer in range [1, 255] inclusive"
    if len(vec0) != len(vec1) or len(vec0) % block_size != 0:
        raise InvalidAssumptions
        
    num_blocks = len(vec0)/block_size
    for i in range(num_blocks):
        low = block_size * i
        up = block_size * (i + 1)
        if vec0[low:up] != vec1[low:up]:
            return i
    return num_blocks
        
def prefixOffset(function, block_size=16, prefix_blocks=0):
    """ Given a function and assuming that it concatenates its
    input with a prefix (and possibly postfix) and then applies
    a block cipher such that each block of the ciphertext 
    depends only on the key and the corresponding block of
    the plaintext (e.g., AES-ECB), and given the block size
    of the cipher and the number of blocks fully occupied by
    the prefix, find the number of bytes remaining in the last
    block touched by the prefix.

    Algorithm:
        (Note: in the illustrations, prefix bytes are
        represented by 'p', postfix bytes by 'P', and
        the block size is taken to be 16. Block labels are
        0-indexed.)

        If the assumption described above is accurate, and
        if the number of blocks fully occupied by the prefix
        is m, and if the number of remaining bytes in the
        last block touched by the prefix is k > 0 , then for
        most cases (i.e., for most values of the suffix) the
        mth and (m + 1)th 0-indexed block of the function's
        output will disagree when the function is given inputs

            '\x00' * (2 * block_size)
        
 ...pp|ppp0000000000000|0000000000000000|000PPPPPPPPPPPPP|PP...
              m - 1            m              m + 1
             
        through
        
            '\x00' * (2 * block_size + (k - 1))

 ...pp|ppp0000000000000|0000000000000000|000000000000000P|PP...
              m - 1            m              m + 1
            
        and then agree when the function is given the input

            '\x00' * (2 * block_size + k).

 ...pp|ppp0000000000000|0000000000000000|0000000000000000|PP...
              m - 1            m              m + 1

        This will be false for certain values of the suffix
        (for example, if '\x00' is the first byte of the 
        suffix) but this issue can be resolved by repeating
        the same procedure with input of '\x01' and taking the
        maximum of the two results.

        If and only if k = 0, then this method will produce the
        value block_size, so we return 0 in that case.

        Args:
            function (function: string -> string): a function
            which satisfies (or probably satisfies) the 
            description above.

            block_size (int): the block size of the cipher used
            by 'function'. Must be in range [1, 255] inclusive.
            Default value is 16.

            prefix_blocks (int): the number of blocks fully
            occupied by the prefix.

            offset (int): the number of bytes remaining (i.e.,
            not belonging to the prefix) in the last block
            touched by the prefix. 

        Returns:
            int: the number of bytes remaining (i.e., not 
            belonging to the prefix) in the last block which 
            contains at least one byte of the prefix. Belongs
            to range [0, 'block_size'-1] inclusive.

        Raises:
            InvalidAssumptions: if the algorithm does not 
            terminate in 'block_size' steps or fewer. This
            may indicate that the block size is incorrect,
            or that other assumptions are invalid. 
        """
    assert (0 < block_size and block_size < 256), "\'block_size\' must be an integer in [1, 255] inclusive"

    low = block_size * (prefix_blocks + 1)
    up = low + 2 * block_size
    chars = ['\x00', '\x01']
    for i in range(1, block_size + 1):       
        tests = [False, False]
        for j in range(2):
            fill = chars[j] * (i + 2 * block_size)
            vec = function(fill)[low:up]
            tests[j] = isAES_ECB(vec)
        if tests[0] and tests[1]:
            if i < block_size:
                return i
            else:
                return 0
    raise InvalidAssumptions

def prefixLength(block_size=16, prefix_blocks=0, offset=0):
    """ Given a block size, the number of blocks fully 
    occupied by a message, and the number of bytes remaining
    in the last block touched by the message, find the length
    of the message.

    Args:
        block_size (int): block_size (int): the block size 
        of the cipher used in 'function'. Must be in range 
        [1, 255] inclusive. Default value is 16.

        prefix_blocks (int): the number of blocks fully 
        occupied by the prefix.

        offset (int): the number of bytes remaining in the 
        last block touched by the prefix.

    Returns:
        int: the number of bytes in the prefix.
    """
    if offset > 0:
        rem = block_size - offset
    else:
        rem = 0
    num_bytes = block_size * prefix_blocks + rem
    return num_bytes

def postfixLength(function, block_size=16, prefix_length=0):
    """ Given a function and assuming that it concatenates its
    input with a prefix and postfix, and then applies
    a block cipher such that each block of the ciphertext 
    depends only on the key and the corresponding block of
    the plaintext (e.g., AES-ECB), and given the block size
    of the cipher and the length of the prefix, find the
    length of the postfix.

    Algorithm:
        Find the length of the output of the function when 
        given the empty string as input. Feed the function
        increasingly long strings of 0 bytes until the
        length of the output jumps up to the next multiple 
        of the block size.

        Here is an illustration of the input to the function's
        cipher. First with the empty string as our input:

    ...pp|pppPPPPPPPPPPPPP|PPPPxxxxxxxxxxxx|
     prefix  ^    postfix      ^  padding

        then with one 0 byte as input:

    ...pp|ppp0PPPPPPPPPPPP|PPPPPxxxxxxxxxxx|

        then more...
     
    ...pp|ppp00000000000PP|PPPPPPPPPPPPPPPPx|
     
        then just enough to make the length jump:

    ...pp|ppp000000000000P|PPPPPPPPPPPPPPPPP|xxxxxxxxxxxxxxxx|
     
        The number of bytes we had to enter to get to 
        the first jump in output length is the number of 
        bytes of padding which appeared at the end of the
        postfix in the input to the function's cipher when
        we fed the empty string to the function. Subtracting
        the number of padding bytes and the length of the
        prefix from the length of the output on the empty
        string, we get the length of the postfix.

    Args:
        function (function: string -> string): a function
        satisfying the assumptions above. 

        block_size (int): the block size 
        of the cipher used in 'function'. Must be in range 
        [1, 255] inclusive. Default value is 16.

        prefix_length (int): the length of the prefix which
        'function' concatenates with messages before
        encryption. Must be a nonnegative integer.

    Returns: 
        int: the length of the postfix which 'function' 
        appends to messages before encryption. A nonnegative
        integer.

    Raises:
        InvalidAssumptions: if the output length does not
        jump in 'block_size' steps or fewer. This may 
        indicate that the specified block size is incorrect.
    """
    assert (0 < block_size and block_size < 256), "\'block_size\' must be an integer in [1, 255] inclusive"
    assert (0 <= prefix_length), "\'prefix_length\' must be a nonnegative integer"

    empt_len = len(function(''))
    for i in range(1, block_size + 1):
        fill = '\x00' * i 
        test_len = len(function(fill))
        if test_len > empt_len:
            break
    if i > block_size:
        raise InvalidAssumptions
    postfix_length = empt_len - prefix_length - i
    return postfix_length

# TODO: improve efficiency and accuracy by testing only a 
# small number of blocks of function(test_vec) with
# isAES_ECB, rather than the whole thing. 
def decryptPostfixByteECB(function, block_size=16, offset=0, prev_bytes='', prev_block='\x00'*16):
    """ Given a function which appends a prefix and suffix 
    to user-supplied messages and then encrypts the result
    with a block cipher in which the encryption of a block
    depends only on the key and the corresponding block of
    the plaintext (e.g., AES-ECB), and some data about the
    function (specified in the arg list) and optionally 
    some known bytes of the postfix, decrypts the next byte
    of the postfix without using the decryption key.

    Args:
        function (function: string -> string):  a function
        which satisfies (or probably satisfies) the 
        description above.

        block_size (int): the block size of the cipher used
        by 'function'. Must be in range [1, 255] inclusive.
        Default value is 16.

        offset (int): the number of bytes remaining in the last
        full block touched by the prefix. Must be in range
        [1, 'block_size' - 1] inclusive.

        prev_bytes (string): the bytes preceding the target
        byte in the same block as the target byte. Must have 
        length in range [0, 'block_size' - 1] inclusive.

        prev_block (string): the block preceding the block 
        containing the target byte. If target byte belongs
        to the first block of the prefix, instead pass
        '\x00' * 'block_size'. Must have length equal to 
        'block_size'.

    Returns:
        char: the ascii-encoded value of the byte of the
        postfix following 'prev_bytes', or of the first 
        byte of the next block of the postfix if 'prev_bytes'
        was empty. 
    """
    assert (0 < block_size and block_size < 256), "\'block_size\' must be a in integer in [1, 255] inclusive."
    assert (0 <= offset and offset < block_size), "\'offset\' must be a positive integer less than \'block_size\'"
    assert (len(prev_bytes) >= 0 and len(prev_bytes) < block_size), "\'prev_bytes\' must have length in [0, \'block_size\' - 1] inclusive."
    assert (prev_block == '' or len(prev_block) == block_size), "If a \'prev_block\' is provided, its length must be equal to \'block_size\'."
    known_len = len(prev_bytes)
    assert (0 <= known_len and known_len < block_size), "The length of \'known_bytes\' must in [0, \'block_size\'-1] inclusive."

    filler_len = block_size - 1 - known_len
    null_fill = '\x00' * block_size
    for k in range(128):
        test_vec = null_fill[:offset] + prev_block[known_len + 1:] + prev_bytes + chr(k) + null_fill[:filler_len]
        if isAES_ECB(function(test_vec)):
            return chr(k)
    return ''

# TODO: the displayed text in verbose mode isn't always aligned
# well (in particular, it's misaligned when the postfix is 
# tools.postfix.) find cause and fix
def decryptPostfixECB(function, verbose=False):
    """ Given a function and assuming that it concatenates its
    input with a prefix and postfix, and then applies
    a block cipher such that each block of the ciphertext 
    depends only on the key and the corresponding block of
    the plaintext (e.g., AES-ECB), decrypt the postfix without
    using the decryption key.

    Args:
        function (function: string -> string): a function which
        satisfies the assumptions described above.
        
        verbose (bool): if True, prints each block of the 
        postfix marquee-style as it is decrypted.

    Returns:
        string: the postfix which 'function' concatenates with
        its input before encryption.
    """
    block_size = findBlockSize(function)
    prefix_blocks = prefixBlocks(function, block_size)
    offset = prefixOffset(function, block_size, prefix_blocks)
    prefix_length = prefixLength(block_size, prefix_blocks, offset)
    postfix_length = postfixLength(function, block_size, prefix_length)
    num_blocks = int(ceil(postfix_length / float(block_size)))

    known_bytes = ''
    out_blocks = ['\x00' * block_size]
    for block in range(num_blocks):
        for ch in range(block_size):
            known_bytes += decryptPostfixByteECB(function, block_size, offset, known_bytes, prev_block=out_blocks[block])
            if verbose:
                print "\033[K", known_bytes, "\r",
                stdout.flush()
        if verbose:
            print ' ' + known_bytes
        out_blocks.append(known_bytes)
        known_bytes = ''
    # slice off garbage bytes in first block and join
    out = ''.join(out_blocks[1:])
    return out

def forgeAdminProfile():
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
    admin_login = False
    while not admin_login:
        ctext1 = newEncrProfile('A'*10 + 'admin' + '\x0b'*11)
        ctext2 = newEncrProfile('A'*12)
        
        forged_ctext = ctext2[:32] + ctext1[16:32]
        login = validateProfile(forged_ctext, verbose=True)
        admin_login = (login['role'] == 'admin')
    return login

############## 6.iii Attacks on AES-CBC ################

def forgeAuthStringCBC(verbose=False):
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
    ctext = newAuthString('')
    current = ';comment2=%20lik'
    admin_login = False
    letter_val = 65
    while not admin_login and letter_val < 127:
        try:
            wish = ';admin=heckyeah' + chr(letter_val)
            if verbose:
                print "trying %s..." % wish
            diff = str(XOR(current, wish))
            new_ctext = ctext[:32] + str(XOR(ctext[32:48], diff)) + ctext[48:]
            admin_login = validateAuthString(new_ctext)
            letter_val += 1
        except:
            letter_val += 1
    if verbose:
        if letter_val < 127:
            print "Success in %d try(s)!" % (letter_val - 65)
        else:
            print "Fail!!"
    return admin_login

def paddingOracleByte(block, prev_block, post_bytes, offset, block_size=16):
    """" Given an implementation of AES-CBC whose decryption
    function rejects strings with invalid PKCS#7 padding, a
    string which is assumed to be a block of an AES-CBC
    ciphertext, a decryption of the last k bytes of 
    the block (where k may be 0), and some other information, 
    decrypt the (k + 1)-th byte from the end of the block
    without using the decryption key.

    Method:
        AES-CBC has the property that flipping the j-th bit in
        the k-th block of a ciphertext results in a flip of 
        the j-th bit of the (k + 1)-th block of the decryption
        of that ciphertext. Therefore, by XOR'ing the block
        before the block containing our target byte with a 
        crafted string, we can set the decryption of the latter
        block to arbitrary strings of length 'block_size'.

        However, if we can't see the output of the AES-CBC 
        decryption, we need a way to find out what our XOR'ing
        has done to the bytes of the block containing our 
        target byte. If the implementation of AES-CBC decryp-
        tion rejects plaintexts with invalid PKCS#7 padding,
        then that provides the information we need. 

        If we know the last k bytes of a block and our target
        byte is the (k + 1)-th byte from the end of that block,
        we XOR the previous block with a test string which
        flips the last k bytes of the decryption of the target
        block to all equal (k + 1), does not affect the first
        'block_size - (k + 1)' bytes of the block, and 
        XORs the (k + 1)-th byte with some char, say 'A'. The 
        resulting plaintext will be accepted by the AES-CBC
        decryption function if and only if it has valid PKCS#7
        padding; i.e., if and only the XOR of the target byte
        with 'A' is equal to the byte value (k + 1). If it is
        accepted, we know that the target byte is equal to
        XOR('A', k + 1). If not, we try again with a different
        test string, say with 'B' instead of 'A', and cycle 
        through the 256 possible values of the target byte 
        until the resulting plaintext has valid padding.

    Args:
        block (string): the block of the ciphertext which
        contains the target byte.

        prev_block (string): the block of the ciphertext which
        precedes the block containing the target byte.

        post_bytes (string): the portion of the decryption of
        'block' which come after the target byte.

        offset (string): the 1-indexed position of the target
        byte from the end of 'block'.

        block_size (string): the block size of the AES cipher.
        Default value is 16.

    Returns: 
        char: the (ascii-encoded) value of the target byte.
    """
    filler_len = block_size - offset 
    null_fill = '\x00' * filler_len
    post_pad = str(XOR(post_bytes, str(bytearray([offset] * (offset-1)))))
    for k in range(128):
        diff = null_fill + str(XOR(chr(k), str(bytearray([offset])))) + post_pad
        new_prev_block = str(XOR(prev_block, diff))
        if validatePadAES_CBC(new_prev_block + block, block_size):
            goal_byte = chr(k)
            # deal with the fact that first guess is often wrong for last byte
            if not (offset == 1 and k == 1):
                break
    goal_byte = chr(k)
    return goal_byte

def paddingOracleBlock(block, prev_block, block_size=16):
    """ Given an implementation of AES-CBC whose decryption
    function rejects strings with invalid PKCS#7 padding, and
    a pair of consecutive blocks of an AES-CBC ciphertext,
    decrypt the second block without using the decryption key.
    
    Method:
        See the docstring of tools.paddingOracleByte.

    Args:
        block (string): the block of the ciphertext which is
        to be decrypted.

        prev_block (string): the block of the ciphertext 
        which precedes 'block'.

        block_size (int): the block size of the AES cipher. 
        Default value is 16.

    Returns:
        string: the decryption of 'block'.
    """
    known_bytes = ''
    for offset in range(1, 17):
        known_bytes = paddingOracleByte(block, prev_block, known_bytes, offset, block_size) + known_bytes
    return known_bytes

def paddingOracle(msg, block_size=16):
    """ Given an implementation of AES-CBC whose decryption
    function rejects strings with invalid PKCS#7 padding, and
    an AES-CBC ciphertext, decrypt the ciphertext without 
    using the decryption key.

    Method:
        See the docstring of tools.paddingOracleByte.

    Args:
        msg: the ciphertext to be decrypted.

        block_size: the block size of the AES cipher. Default
        value is 16.

    Returns:
        string: the decryption of 'msg'.
    """
    blocks = blockify(msg, 'ascii', block_size, extra=False)
    known_blocks = []
    for ind in range(1, len(blocks)):
        known_blocks.append(paddingOracleBlock(blocks[ind], blocks[ind - 1], block_size))
    decryption = ''.join(known_blocks)
    return decryption

# TODO: occasionally (~ 1 in 20 runs) this function will throw
# an error due to two args of tools.XOR being of unequal 
# lengths. Unclear how to reproduce, try again.
def decryptSeries(verbatim=False):
    """ Given an implementation of AES-CBC which rejects
    plaintexts with invalid PKCS#7 padding, and an
    oracle which produces AES-CBC encryptions of random
    messages chosen from the list tools.set3ch17_texts, 
    identify and decrypt all 10 of the messages in that list
    without using the decryption key. 

    Note that a couple of the plaintexts have missing
    letters (presumably to squish them into a specific
    number of bytes). This is intended, as you can check
    by decrypting the ciphertexts directly!

   Method:
        The decryption itself is done using a padding oracle.
        For the idea, see the docstring of
        tools.paddingOracleByte. 

        The 10 messages in set3ch17_ctexts turn out to have
        structured prefixes which encode their order. Until
        we have found all of them, we keep asking
        tools.CBCOracle for encryptions of random messages
        from the list, decrypt the messages using
        tools.paddingOracle, save messages we haven't seen 
        yet and throw out the ones we have.
        
    Args: 
        verbatim (bool): if True, print decryptions
        in verbatim mode; if False, pretty-print.

    Returns:
       string: the 10 plaintexts concatentated
       into one string, separated by newlines. 
    """
    found = [False] * 10
    decrypts = [''] * 10
    while found != [True] * 10:
        decrypt = paddingOracle(CBCOracle())
        line_num = int(decrypt[5])
        if not found[line_num]:
            decrypts[line_num] = decrypt
            found[line_num] = True
            print "Found line", line_num
    if verbatim:
        series = '\n'.join([repr(decrypt) for decrypt in decrypts])
    else:
        decrypts_strip = []
        for decrypt in decrypts:
            try:
                decrypts_strip.append(stripPad(decrypt, block_size=16))
            except BadPad:
                decrypts_strip.append(decrypt)
        series = '\n'.join(decrypts_strip)
    return series

# TODO: test and document
def findAuthAffixLenCTR():
    prefix_len, suffix_len = 0, 0
    auth1 = newAuthStringCTR('\x00')
    auth2 = newAuthStringCTR('\x01')
    diff = encode(XOR(auth1, auth2), 'ascii')
    for k in range(len(diff)):
        if diff[k] != '\x00':
            prefix_len = k
    suffix_len = len(auth1) - 1 - prefix_len 
    return (prefix_len, suffix_len)

def forgeAuthStringCTR():
    auth = newAuthStringCTR('\x00' * 18)
    (prefix_len, suffix_len) = findAuthAffixLenCTR()
    new_data = '\x00' * prefix_len + 'he;ll=o;admin=true' + '\x00' * suffix_len
    new_auth = encode(XOR(new_data, auth), 'ascii')
    return new_auth


############### 6.iv. Attacks on RNGs #################

# TODO: document
# TODO: parallelize this someday
def mtCrackSeed(val, start, end):
    for sec in range(start, end):
        twister = mt19937(sec)
        if twister.next() == val:
            return sec
    print "No matching seed found"
    return None

# TODO: document
def mtClone(twister):
    state = [mtUntemper(twister.next()) for i in range(624)]
    clone = mt19937(0)
    clone.state = state 
    return clone

# TODO: is it appropriate to return None here? or better to throw an exception?
# TODO: parallelize this someday
def mtOracleFindSeed(oracle, user_input, verbose=False):
    ctext = oracle(user_input)
    known_len = len(user_input)
    prefix_len = len(ctext) - known_len
    known_ctext = ctext[prefix_len:]
    keystream = [0] * known_len
    for i in range(known_len):
        ctext_byt = known_ctext[i]
        known_byt = user_input[i]
        keystream[i] = ord(str(XOR(ctext_byt, known_byt)))
    
    if verbose:
        print "ciphertext returned by oracle: ", repr(ctext)
        print "searching for seed..."
    for test_seed in range(2**16):
        twister = mt19937(test_seed)
        for j in range(prefix_len):
            twister.next()
        for k in range(known_len):
            test_byt = (twister.next() & 0xFF)
            if test_byt != keystream[k]:
                break
            if k == known_len - 1:
                return test_seed
    return None

# TODO: document. assume (??) that tokens are encryptions of prefixes + userid. (can this assumption be improved?). also assume seeds are 16-bit
def isTimeSeededMT(oracle, userid):
    if mtOracleFindSeed(oracle, userid):
        return True
    else:
        return False

# TODO: test and document
def findKeyStreamByteCTR(ctext, offset, ctext_format='ascii'):
    for k in range(256):
        edit = editAPI_CTR(ctext, offset, chr(k), ctext_format)
        if edit[offset] == 0:
            return chr(k)
    return None

# TODO: test and document
def crackEditableCTR(ctext, ctext_format='ascii'):
    ctext_bytes = encode(decode(ctext, ctext_format), 'ascii')
    keystream = ''
    for offset in range(len(ctext_bytes)):
        keystream += findKeyStreamByteCTR(ctext, offset, ctext_format)
    ptext = XOR(ctext, keystream, ctext_format, 'ascii')
    return ptext

