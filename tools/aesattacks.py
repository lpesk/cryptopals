from tools.message import Message, listBlocks, joinBlocks
from tools.bitops import XOR
from tools.aes import AES_ECB, AES_CBC, AES_CTR
from tools.freqanalysis import guessRepXORKey
from math import ceil
from sys import stdout

class InvalidAssumptions(Exception):
    """ Exception raised when some assumptions required by
    a test or attack are likely not valid. """
    def __init__(self):
        Exception.__init__(self, "The assumptions of this method are likely not valid.")

def isAES_ECB(msg):
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
    blocks = listBlocks(msg)
    indices = [(i, j) for i in range(len(blocks)) for j in range(i)]
    for (i, j) in indices:
        if blocks[i] == blocks[j]:
            return True
    return False

def findBlockSize(oracle, upper_bound=256):
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
    assert (1 <= upper_bound and upper_bound <= 256), "upper_bound must be an integer in range [1, 256] inclusive."

    init_length = len(oracle(Message(b'')))
    block_size = 0
    for k in range(upper_bound):
        test_len = len(oracle(Message(b'\x00' * k)))
        if test_len > init_length:
            block_size = test_len - init_length
            return block_size
    raise InvalidAssumptions

def decryptPostfixByteECB(oracle, block_size=16, offset=0, prev_bytes='', prev_block=None):
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
    assert (0 < block_size and block_size < 256), "\'block_size\' must be a in integer in [1, 256] inclusive."
    assert (0 <= offset and offset < block_size), "\'offset\' must be a positive integer less than \'block_size\'"
    assert (len(prev_bytes) >= 0 and len(prev_bytes) < block_size), "\'prev_bytes\' must have length in [0, \'block_size\' - 1] inclusive."
    
    known_len = len(prev_bytes)
    assert (0 <= known_len and known_len < block_size), "The length of \'known_bytes\' must be in [0, \'block_size\'-1] inclusive."

    if prev_block is None:
        prev_block = Message(b'\x00' * block_size)
    assert (len(prev_block) == block_size), "If a \'prev_block\' is provided, its length must be equal to \'block_size\'."

    filler_len = block_size - 1 - known_len
    null_fill = Message(b'\x00' * block_size)
    for test_byte in [Message(bytes([k])) for k in range(256)]:
        test_vec = prev_block[known_len + 1:] + prev_bytes + test_byte
        padded_test_vec = null_fill[:offset] + test_vec + null_fill[:filler_len]
        ciphertext = oracle(padded_test_vec)
        if isAES_ECB(ciphertext):
            return test_byte
    return Message(b'')

def prefixBlocks(oracle, block_size=16):
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
    vec0 = oracle(Message(b'\x00'))
    vec1 = oracle(Message(b'\x01'))

    assert (1 <= block_size and block_size <= 256), "\'block_size\' must be an integer in range [1, 256] inclusive"
    if len(vec0) != len(vec1) or len(vec0) % block_size != 0:
        raise InvalidAssumptions
        
    num_blocks = int(len(vec0)/block_size)
    for k in range(num_blocks):
        low = block_size * k
        high = block_size * (k + 1)
        if vec0[low:high] != vec1[low:high]:
            return k
    return num_blocks
        
def prefixOffset(oracle, block_size=16, prefix_blocks=0):
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
    assert (1 <= block_size and block_size <= 256), "\'block_size\' must be an integer in [1, 256] inclusive"

    low = block_size * (prefix_blocks + 1)
    high = low + 2 * block_size
    chars = [Message(b'\x00'), Message(b'\x01')]
    for k in range(1, block_size + 1):       
        tests = [False, False]
        for j in range(2):
            fill = chars[j] * (k + 2 * block_size)
            vec = oracle(fill)[low:high]
            tests[j] = isAES_ECB(vec)
        if tests[0] and tests[1]:
            if k < block_size:
                return k
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

def postfixLength(oracle, block_size=16, prefix_length=0):
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
    assert (1 <= block_size and block_size <= 256), "\'block_size\' must be an integer in [1, 256] inclusive"
    assert (0 <= prefix_length), "\'prefix_length\' must be a nonnegative integer"

    empty_len = len(oracle(Message(b'')))
    for k in range(1, (block_size + 1)):
        fill = Message(b'\x00' * k)
        test_len = len(oracle(fill))
        if test_len > empty_len:
            break
    if k > block_size:
        raise InvalidAssumptions
    postfix_length = empty_len - prefix_length - k
    return postfix_length

# TODO: the displayed text in verbose mode isn't always aligned
# well (in particular, it's misaligned when the postfix is 
# tools.postfix.) find cause and fix
def decryptPostfixECB(oracle):
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
    block_size = findBlockSize(oracle)

    prefix_blocks = prefixBlocks(oracle, block_size)
    offset = prefixOffset(oracle, block_size, prefix_blocks)
    prefix_length = prefixLength(block_size, prefix_blocks, offset)
    postfix_length = postfixLength(oracle, block_size, prefix_length)
    num_blocks = int(ceil(postfix_length / block_size))

    known_bytes = Message(b'')
    out_blocks = [Message(b'\x00' * block_size)]
    for block in range(num_blocks):
        for ch in range(block_size):
            known_bytes += decryptPostfixByteECB(oracle, block_size, offset, known_bytes, prev_block=out_blocks[block])
        out_blocks.append(known_bytes)
        known_bytes = Message(b'')
    # slice off garbage bytes in first block and join blocks
    out = joinBlocks(out_blocks[1:])
    return out

def forgeAdminCookie(verbose=False):
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
    cookie = newUserCookie('')
    current = Message(b';comment2=%20lik')
    new_cookie = Message(b'')
    admin_login = False
    letter_val = 65
    while not admin_login and letter_val < 127:
        try:
            wish = Message(b';admin=true;xx=') + Message(bytes([letter_val]))
            if verbose:
                print("trying %s..." % repr(wish.ascii()))
            diff = XOR(current, wish)
            new_cookie = cookie[:32] + XOR(cookie[32:48], diff) + cookie[48:]
            admin_login = isAdminCookie(new_cookie)
            letter_val += 1
        except:
            letter_val += 1
    if verbose:
        if letter_val < 127:
            print("Success in %d try(s)!" % (letter_val - 65))
        else:
            print("Fail!!")
    return new_cookie

def paddingOracleByte(validation_oracle, block, prev_block, post_bytes, offset, block_size=16):
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
    null_fill = Message(b'\x00' * filler_len)
    post_pad = XOR(post_bytes, Message(bytes([offset] * (offset-1))))
    for k in range(256):
        diff = null_fill + XOR(Message(bytes([k])), Message(bytes([offset]))) + post_pad
        new_prev_block = XOR(prev_block, diff)
        if validation_oracle(new_prev_block + block):
            goal_byte = Message(bytes([k]))
            # deal with the fact that first guess is often wrong for last byte
            if not (offset == 1 and k == 1):
                break
    goal_byte = Message(bytes([k]))
    return goal_byte

def paddingOracleBlock(validation_oracle, block, prev_block, block_size=16):
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
    known_bytes = Message(b'')
    for offset in range(1, 17):
        known_bytes = paddingOracleByte(validation_oracle, block, prev_block, known_bytes, offset, block_size) + known_bytes
    return known_bytes

def paddingOracle(validation_oracle, msg, block_size=16):
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
    blocks = listBlocks(msg, block_size)
    known_blocks = []
    for index in range(1, len(blocks)):
        known_blocks.append(paddingOracleBlock(validation_oracle, blocks[index], blocks[index - 1], block_size))
    decryption = joinBlocks(known_blocks)
    return decryption

def breakRepNonceCTR(ciphertext_list):
    min_len = min(len(line) for line in ciphertext_list)
    ciphertext = Message(b''.join(line[:min_len].bytes for line in ciphertext_list))
    guess_key = guessRepXORKey(ciphertext, key_size=min_len)
    return guess_key

