from tools.message import Message, listBlocks, joinBlocks
from tools.bitops import XOR
from Crypto.Cipher import AES

valid_fns = ['encrypt', 'decrypt']

class InvalidFn(Exception):
    """ Exception raised when an invalid string is
    passed as a cipher operation.
    """
    def __init__(self):
        Exception.__init__(self, "Invalid cipher operation. Valid options are: %s." % ', '.join(['\'' + mode + '\'' for fn in valid_fns]))

def AES_ECB(msg, key, fn='encrypt', extra=True):
    """ Encrypts or decrypts a message under a specified key
    using AES in ECB mode.

    Args:
        msg (Message): the message to be en/decrypted.
        
        key (Message): the key to be used for en/decryption.

        fn (string): the operation which should be performed
        using the cipher. Options are 'encrypt' (default) and
        'decrypt'.
        
        extra (bool): if True, expect that padding scheme
        always adds padding bytes to messages even if the 
        length of the message is a multiple of the block
        size (as PKCS#7 padding requires); if False, expect
        that padding bytes are added only if length of the
        message is not a multiple of the block size (as is
        desirable for non-terminal message blocks in AES-CBC). 

    Returns:
        Message: the en/decryption of 'msg'
        under 'key' using AES in ECB mode.
    """
    if fn not in valid_fns:
        raise InvalidFn

    cipher = AES.new(key.bytes, AES.MODE_ECB)
    if fn == 'encrypt':
        blocks = listBlocks(msg.pad(16, extra))
        out_blocks = [Message(cipher.encrypt(block.bytes)) for block in blocks]
    else:
        blocks = listBlocks(msg)
        out_blocks = [Message(cipher.decrypt(block.bytes)) for block in blocks]
    return joinBlocks(out_blocks)

def AES_CBC(msg, key, iv='', fn='encrypt'):
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
    """
    assert(len(key) == 16), "Key must be 16 bytes long"
    if fn == 'encrypt' or iv:
        assert(len(iv) == 16), "IV must be 16 bytes long"
    if fn not in valid_fns:
        raise InvalidFn

    out_blocks = []
    if fn == 'encrypt':
        in_blocks = listBlocks(msg.pad())
        out_blocks.append(iv)
        for k in range(len(in_blocks)):
            new_block = AES_ECB(XOR(in_blocks[k], out_blocks[k]), key, 'encrypt', extra=False)
            out_blocks.append(new_block)
    else:
        in_blocks = listBlocks(msg)
        if iv:
            in_blocks = [iv] + in_blocks
            # otherwise, assume that the first block of msg is the iv
        for k in range(1, len(in_blocks)):
            new_block = XOR(AES_ECB(in_blocks[k], key, 'decrypt', extra=False), in_blocks[k-1])
            out_blocks.append(new_block)
    return joinBlocks(out_blocks)


def keystreamCTR(key, length, offset=0, nonce=None, block_size=16):
    if nonce is None:
        nonce = Message(b'\x00' * int(block_size / 2))
    start_block = int(offset / block_size)
    end_block = int((offset + length) / block_size)
    start_block_offset = offset % block_size
    keystream = Message(b'')
    ctr = start_block
    while ctr <= end_block:
        ctr_msg = nonce + Message(hex(ctr).lstrip('0x').rjust(16, '0'), 'hex', 'little')
        keystream += AES_ECB(ctr_msg, key, fn='encrypt', extra=False)
        ctr += 1
    keystream = keystream[start_block_offset: start_block_offset + length]
    return keystream
        
def AES_CTR(msg, key, nonce=None, block_size=16):
    keystream = keystreamCTR(key, len(msg), 0, nonce, block_size)
    return XOR(msg, keystream)
    
