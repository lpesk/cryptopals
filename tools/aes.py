from tools.bitops import XOR
from tools.message import joinBlocks, listBlocks, Message

from Crypto.Cipher import AES

valid_fns = ['encrypt', 'decrypt']

class InvalidFn(Exception):
    """ Exception raised when an invalid string is passed as a cipher operation.
    """
    def __init__(self):
        Exception.__init__(self, "Invalid cipher operation. Valid options are: %s." % ', '.join(['\'' + mode + '\'' for fn in valid_fns]))

def AES_ECB(msg, key, fn='encrypt', strict=True):
    """ Encrypts or decrypts a message under a specified key using AES in ECB mode.

    Args:
        msg (Message): the message to be en/decrypted.
        
        key (Message): the key to be used for en/decryption.

        fn (string): the operation which should be performed using the cipher. Options are 'encrypt' (default) and 'decrypt'.
        
        strict (bool): if True, expect that padding scheme always adds padding bytes to messages even if the length of the message is a multiple of the block size (as PKCS#7 padding requires); if False, expect that padding bytes are added only if length of the message is not a multiple of the block size (as is desirable for non-terminal message blocks in AES-CBC). 

    Returns:
        Message: the en/decryption of 'msg' under 'key' using AES in ECB mode.

    Raises:
        InvalidFn: if 'fn' is not equal to 'encrypt' or 'decrypt'.
    """
    if fn not in valid_fns:
        raise InvalidFn

    cipher = AES.new(key.bytes, AES.MODE_ECB)
    if fn == 'encrypt':
        blocks = listBlocks(msg.pad(16, strict))
        out_blocks = [Message(cipher.encrypt(block.bytes)) for block in blocks]
    else:
        blocks = listBlocks(msg)
        out_blocks = [Message(cipher.decrypt(block.bytes)) for block in blocks]
    return joinBlocks(out_blocks)

def AES_CBC(msg, key, iv=Message(b''), fn='encrypt'):
    """ Encrypts or decrypts a message under a specified key using AES in CBC mode.

    When encrypting, the user should provide an initial value (IV), consisting of one block, as the 'iv' argument. The IV is used during encryption and then prepended to the encrypted message before returning. The IV which was used during encryption must also be supplied during decryption. When decrypting, the user may either leave the 'iv' argument empty, in which case the first block of the 'msg' argument is assumed to be the IV, or may provide the IV as the 'iv' argument.

    Args:
        msg (Message): the message to be en/decrypted.
        
        key (Message): the key to be used for en/decryption. Must have length 16.

        iv (Message): the initialization vector to be used for en/decryption. Must have length 16, unless 'fn' is 'decrypt', in which case it may be empty: during decryption, if 'iv' is the empty message then the first 16 bytes of 'msg' will be treated as the IV.

        fn (string): the operation which should be performed using the cipher. Options are 'encrypt' (default) and 'decrypt'.

    Returns:
        Message: the encryption of 'msg' under 'key' under AES-CBC with IV 'iv'. 

    Raises:
        AssertionError,  "Key must be 16 bytes long": if the key length is incorrect.

        AssertionError, "IV must be 16 bytes long": if the IV length is incorrect. 
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
            new_block = AES_ECB(XOR(in_blocks[k], out_blocks[k]), key, 'encrypt', strict=False)
            out_blocks.append(new_block)
    else:
        in_blocks = listBlocks(msg)
        if iv:
            in_blocks = [iv] + in_blocks
            # otherwise, assume that the first block of msg is the iv
        for k in range(1, len(in_blocks)):
            new_block = XOR(AES_ECB(in_blocks[k], key, 'decrypt', strict=False), in_blocks[k-1])
            out_blocks.append(new_block)
    return joinBlocks(out_blocks)

def AES_CBC_IVKey(msg, key, fn='encrypt'):
    """
    Encrypt a message under a key using AES-CBC, reusing the key as the IV. 

    note: while this is insecure as a means of encryption, it has been used as a means of obfuscation, e.g. in pluggable transports to disguise tor traffic (cf. hyphae paper)
    """
    block_size = 16
    if fn is 'encrypt':
        return AES_CBC(msg, key, key, 'encrypt')[block_size:]
    else:
        return AES_CBC(msg, key, key, 'decrypt')

def keystreamCTR(key, length, offset=0, nonce=None, block_size=16):
    """
    Generate a sequence of keystream bytes, of a specified length and beginning at a specified offset, for AES in CTR mode. 

    Args:
        key (Message): the symmetric key to be used for en/decryption. Must have length equal to 'block_size'.

        length (int): the length of the desired keystream. Must be a positive integer.

        offset (int): the offset into the full keystream of the first byte of the sequence. Must be a nonnegative integer; default value is 0.

        nonce (Message): a one-time Message instance used to randomize the keystream. Must have length equal to 'block_size'/2. Default value is a message of zero bytes of appropriate length.

        block_size (int): the length in bytes of a block. Must be an even integer in range [2, 254] inclusive. Default value is 16.

    Returns:
        Message: the portion of the keystream of length 'length' and beginning at 'offset' bytes into the full AES-CTR keystream produced using key 'key' and nonce 'nonce. 

    Raises:
        AssertionError, "Block size must be an even integer in range [2, 254] inclusive": if 'block_size' is invalid.
        
        AssertionError, "Length of keystream must be positive": if 'length' is invalid.

        AssertionError, "Offset must be nonnegative": if 'offset' is invalid.
    """
    assert (0 < block_size and block_size < 256 and block_size % 2 == 0), "Block size must be an even integer in range [2, 254] inclusive"
    assert(0 < length), "Length of keystream must be positive"
    assert(0 <= offset), "Offset must be nonnegative"
    if nonce is None:
        nonce = Message(b'\x00' * int(block_size / 2))
    start_block = int(offset / block_size)
    end_block = int((offset + length) / block_size)
    start_block_offset = offset % block_size
    keystream = Message(b'')
    ctr = start_block
    while ctr <= end_block:
        ctr_msg = nonce + Message(hex(ctr).lstrip('0x').rjust(16, '0'), 'hex', 'little')
        keystream += AES_ECB(ctr_msg, key, fn='encrypt', strict=False)
        ctr += 1
    keystream = keystream[start_block_offset: start_block_offset + length]
    return keystream
        
def AES_CTR(msg, key, nonce=None, block_size=16):
    """
    Encrypt, or, equivalently, decrypt a message under a specified key and nonce using AES-CTR. 

    Args:
        msg (Message): the message to be en/decrypted.

        key (Message): the symmetric key to be used for en/decryption. Must have length equal to 'block_size'.

        nonce (Message): a one-time Message instance used to randomize the keystream. Must have length equal to 'block_size'/2. Default value is a message of zero bytes of appropriate length.

        block_size (int): the length in bytes of a block. Must be an even integer in range [2, 254] inclusive. Default value is 16. 

    Returns:
        Message: the en/decryption of 'msg' under 'key' using AES-CTR with nonce 'nonce'.
    """
    keystream = keystreamCTR(key, len(msg), 0, nonce, block_size)
    return XOR(msg, keystream)
