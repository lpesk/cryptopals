from base64 import b16decode, b16encode, b64decode, b64encode

""" valid_formats: list of valid format options for all 
functions operating on strings.
"""
valid_formats = ['ascii', 'base64', 'bin', 'bytes', 'hex', 'int']

valid_ends = ['big', 'little']

class InvalidFormat(Exception):
    """ Exception raised when an invalid string is
    passed as a format name.
    """
    def __init__(self):
        Exception.__init__(self, "Invalid format option. Valid options are: %s." % ', '.join(['\'' + fmt + '\'' for fmt in valid_formats]))

class InvalidEndian(Exception):
    """ Exception raised when an invalid string is
    passed as an endian flag.
    """
    def __init__(self):
        Exception.__init__(self, "Invalid endian option. Valid options are: %s." % ', '.join(['\'' + fmt + '\'' for fmt in valid_ends]))

class BadPad(Exception):
    """ Exception raised when an attempt to interpret 
    the tail of a string as PKCS#7 standard padding
    has failed. 
    """
    def __init__(self):
        Exception.__init__(self, "Incorrect padding")

def _decode(msg, msg_format, end='big'):
    """ Form a big-endian byte string from one of the following representations: an ascii-, base64-, binary-, hex-, or base64-encoded string, a nonnegative integer, or a byte string (in the last case no operation is done except possibly to reverse endianness).

    Args:
        msg (string): a representation of a sequence of bytes.

        msg_format (string): the encoding of the bytes represented by 'msg'. Options are the members of the list 'valid_formats': 'bytes', 'ascii', 'base64', 'bin', 'hex', and 'int'. 

        end (string): the endianness of the representation of the bytes in 'msg'. Options are the members of the list 'valid_ends': big' (default) and 'little'.

    Returns:
        bytes: a byte string containing the bytes represented by 'msg'. 

    Raises:
        InvalidFormat: if 'msg_format' is nonempty and not in 'valid_formats'.

        InvalidEndian: if 'end' is not in 'valid_ends'. 

        Exception, "Argument 'msg' cannot be interpreted as an integer": if a non-integer type is passed as 'msg' while 'int' is passed as 'msg_format'.

        Exception, "Argument 'msg' must be a nonnegative integer": if a negative integer is passed as 'msg' while 'int' is passed as 'msg_format'.
    """
    if msg_format not in valid_formats:
        raise InvalidFormat
    if end not in valid_ends:
        raise InvalidEndian

    if msg_format == 'bytes':
        msg_bytes = msg

    elif msg_format == 'ascii':
        msg_bytes = bytes(msg, 'utf-8')

    elif msg_format == 'bin':
        if len(msg) % 8 != 0:
            raise Exception("Length of binary string must be a multiple of 8")
        byt_len = int(len(msg)/8)
        msg_bytes = b''.join(bytes([int(msg[k*8:(k+1)*8], 2)]) for k in range(byt_len))

    elif msg_format == 'hex':
        msg_bytes = b16decode(bytes(msg, encoding='utf-8'), True)

    elif msg_format == 'int':
        if not isinstance(msg, int):
            raise Exception("Argument 'msg' cannot be interpreted as an integer")
        elif msg < 0:
            raise Exception("Argument 'msg' must be a nonnegative integer")
        elif msg == 0:
            msg_bytes = b''
        else:
            msg_hex = hex(msg).lstrip('0x')
            pad = '0' if len(msg_hex) % 2 else ''
            msg_bytes = _decode(pad + msg_hex, 'hex')

    else:
        msg_bytes = b64decode(bytes(msg, encoding='utf-8'))

    if end == 'little':
        msg_bytes = msg_bytes[::-1]

    return msg_bytes

def _encode(msg_bytes, out_format, end='big'):
    """ Convert a big-endian byte string into any of the following forms: an ascii-, base64-, binary-, or hex-encoded string, a nonnegative integer, or a byte string (in the last case no operation is done except to possibly reverse the endianness).

    Args:
        msg_bytes (bytes): the byte string to be encoded.

        out_format (string): the desired encoding of the bytes of 'msg_bytes' in the output. Options are the members of 'valid_formats': 'ascii', 'base64', 'bin', 'bytes', 'hex', and 'int'. 

        end (string): the desired endianness of the encoded representation of 'msg_bytes'. Options are the members of 'valid_ends': 'big' (default) and 'little'. 

    Returns:
        string (if 'out_format' is 'ascii', 'base64', 'bin', or 'hex'): string representing the bytes of 'msg_bytes', with encoding 'out_format' and endianness 'end'.
        
        bytes (if 'out_format' is 'bytes'): byte string representing the bytes of 'msg_bytes' with endianness 'end'.

        int (if 'out_format' is 'int'): integer representing the bytes of 'msg_bytes' with endianness 'end'.
 
    Raises:
        InvalidFormat: if 'out_format' is nonempty and not in 'valid_formats'.

        InvalidEndian: if 'end' is not in 'valid_ends'.
    """
    if out_format not in valid_formats:
        raise InvalidFormat
    if end not in valid_ends:
        raise InvalidEndian

    if end == 'little':
        msg_bytes = msg_bytes[::-1]

    if out_format == 'bytes':
        return msg_bytes

    elif out_format == 'bin':
        return ''.join(bin(byt).lstrip('0b').zfill(8) for byt in msg_bytes)

    elif out_format == 'int':
        if msg_bytes == b'':
            return 0
        else:
            return int(_encode(msg_bytes, 'hex'), 16)

    elif out_format == 'ascii':
        msg = msg_bytes

    elif out_format == 'hex':
        msg = b16encode(msg_bytes).lower()

    else:
        msg = b64encode(msg_bytes)
    return msg.decode('utf-8')

        
class Message():
    """ A wrapper class for the bytes type. Supports construction from any of the following formats: bytes, int (positive only), and ascii-, base64-, binary-, or hex-encoded string. Class methods also support encoding of a Message instance in any of these formats. Both big- and little-endian representations are supported.

    Special methods provide support for hashing, slicing, addition, and scalar multiplication. Slices (including slices of size 1) are again Message instances.

    Class methods support padding and pad-stripping/validation according to the PKCS#7 standard and a variant.
    """
    def __init__(self, msg, msg_format='bytes', end='big'):
        if msg_format not in valid_formats:
            raise InvalidFormat
        elif end not in valid_ends:
            raise InvalidEndian
        elif msg_format == 'bytes':
            self.bytes = msg
        else:
            self.bytes = _decode(msg, msg_format, end)

    def __repr__(self):
        return "Message(%s)" % repr(self.bytes)

    def __hash__(self):
        return hash(self.bytes)

    def __len__(self):
        return len(self.bytes)

    def __getitem__(self, key):
        if isinstance(key, int):
            return Message(bytes([self.bytes[key]]))
        elif isinstance(key, slice):
            return Message(self.bytes[key])
        else:
            raise Exception

    def __lt__(self, other):
        return (self.bytes < other.bytes)

    def __le__(self, other):
        return (self.bytes <= other.bytes)

    def __eq__(self, other):
        return (self.bytes == other.bytes)

    def __ne__(self, other):
        return (self.bytes != other.bytes)

    def __gt__(self, other):
        return (self.bytes > other.bytes)
    
    def __ge__(self, other):
        return (self.bytes >= other.bytes)

    def __add__(self, other):
        return Message(self.bytes + other.bytes)
    
    def __mul__(self, rep):
        return Message(self.bytes * rep)

    def join(self, msg_list):
        return Message(self.bytes.join(msg.bytes for msg in msg_list))

    def split(self, msg_byt):
        return [Message(sub) for sub in (self.bytes).split(msg_byt.bytes)]

    def ascii(self):
        return _encode(self.bytes, 'ascii')

    def bin(self, end='big'):
        return _encode(self.bytes, 'bin', end)

    def hex(self, end='big'):
        return _encode(self.bytes, 'hex', end)

    def int(self, end='big'):
        return _encode(self.bytes, 'int', end)

    def base64(self, end='big'):
        return _encode(self.bytes, 'base64', end)
        
    def pad(self, block_size=16, strict=True):
        """
        Apply padding to self.bytes in order to increase len(self) to a multiple of the positive integer 'block_size'. The padding bytes are each equal to the length of the pad.

        When keyword argument 'strict' is True, the behavior of 'pad' is consistent with the PKCS#7 standard. 

        Args:
            self (Message): the Message instance to be padded.

            block_size (int): the positive integer which should evenly divide the length of the padded message. Must be in [1, 255] inclusive; default value is 16.

            strict (bool): If keyword argument 'strict' is True, apply a full block of padding when len(self) is already a multiple of 'block_size'. If 'strict' is False, only apply padding when len(self) is not a multiple of 'block_size'. 

        Returns:
            Message: the Message instance 'self', modified in place to add any padding. 

        Raises:
            AssertionError: if 'block_size' is nonpositive or greater than 255.
        """
        assert (0 < block_size and block_size < 256), "Block size must be an integer in [1, 255] inclusive"
        if len(self) % block_size == 0:
            if strict:
                pad_size = block_size
            else:
                return self
        else:
            steps = (int(len(self)/block_size)) + 1
            pad_size = block_size * steps - len(self)
        pad_bytes = bytes([pad_size] * pad_size)
        self.bytes += pad_bytes
        return self

    def stripPad(self, block_size=16, strict=True):
        """
        Detect and remove padding from Message instances. The expected padding scheme is that provided by message.pad.

        When keyword argument 'strict' is True, behavior of 'stripPad' is consistent with the PKCS#7 padding standard.

        Args:
            self (Message): the Message instance to be de-padded.

            block_size (int): the upper bound (inclusive if 'strict' is True, exclusive otherwise) on the length of the pad.

            strict (bool): if True, detect and remove padding produced by the function message.pad with keyword argument 'strict' == True; otherwise detect and remove padding produced by message.pad with 'strict' == False.

        Returns:
            Message: the Message instance 'self', modified in place to remove any padding.

        Raises:
            AssertionError, "Message must be nonempty": if an empty message is passed as 'self'.
            
            AssertionError, "Block size must be an integer in [1, 255] inclusive": if an out-of-range integer is passed as 'block_size'.

            BadPad: if keyword argument 'strict' is True and argument 'self' does not have valid PKCS#7 padding. 
        """
        assert (self != Message(b'')), "Message must be nonempty"
        assert (0 < block_size and block_size < 256), "Block size must be an integer in [1, 255] inclusive"
        poss_pad_size = int(self.bytes[-1])
        in_bounds = (poss_pad_size >= 1 and poss_pad_size <= block_size)
        if in_bounds:
            poss_pad = self.bytes[-1 * poss_pad_size:]
        elif strict:
            raise BadPad
        else:
            return self

        if (poss_pad == bytes([self.bytes[-1]]) * poss_pad_size):
            self.bytes = self.bytes[:-1 * poss_pad_size]
            return self
        elif strict:
            raise BadPad
        else:
            return self

    def validatePad(self, block_size=16):
        """ Decide whether a Message instance has been padded to a specified block size according to the PKCS#7 standard. If so, strip off the padding and return True; if not, return False.

        Args:
            self (Message): the Message instance whose padding is to be validated and stripped.

            block_size (int): the block size which is expected to divide the padded length of 'self'. Must be a positive integer less than 256; default value is 16.

        Returns:
            bool: True if 'self' had valid PKCS#7 padding to a multiple of 'block_size', False if not. When True is returned, padding is also stripped in place from 'self'.
        """
        try:
            self.stripPad()
            return True
        except BadPad:
            return False        

    def validateAscii(self):
        """
        Given a message, return True if all bytes of the message have ascii values in the range [0, 127] inclusive, and False otherwise.

        Args:
            self (Message): the Message instance whose bytes are to be validated.

        Returns:
            bool: True if all bytes of 'self.bytes' are in range [0, 127] inclusive; False otherwise.
        """
        for byt in self.bytes:
            if byt >= 127:
                return False
        return True
        
    def eatChars(self, char_list):
        """ Given a Message and a list of bytes, remove all occurances of the specified bytes from the message.

        Args: 
            self (Message): the message to be modified.

            char_list (list of bytes): a list of all bytes to be removed from 'self.bytes'.

        Returns:
            Message: the modification in place of 'self' to remove all specified bytes from 'self.bytes'.
        """
        for msg_byt in char_list:
            self.bytes = self.bytes.replace(msg_byt.bytes, b'')
        return self
    
def listBlocks(msg, block_size=16):
    """
    Given a Message instance and a block size, divide the message into a list of messages of size 'block_size' (except possibly the last message, which may be shorter).

    Args:
        msg (Message): the message to be split into blocks.

        block_size (int): the desired length of the blocks. Must be an integer in range [1, 255] inclusive.

    Returns:
        list of Message instances: a list of the blocks of size 'block_size' formed from 'msg'.

    Raises:
        AssertionError, "Block size must be an integer in range [1, 255] inclusive": if an invalid 'block_size' is passed.
    """
    assert (0 < block_size and block_size < 256), "Block size must be an integer in range [1, 255] inclusive"
    num_blocks = int(len(msg)/block_size)
    blocks = [Message(msg.bytes[block_size * i: block_size * (i+1)]) for i in range(num_blocks)]
    if len(msg) % block_size != 0:
        blocks.append(Message(msg.bytes[block_size * num_blocks:]))
    return blocks

def joinBlocks(msg_blocks):
    """
    Given a list of Message instances, concatentate them to form a single Message instance.

    Args:
        msg_blocks (list of Message instances): the Message instances to be concatenated.

    Returns:
        Message: the concatenation of the messages in the list 'msg_blocks'. 
    """
    msg = Message(b'')
    for block in msg_blocks:
        msg.bytes += block.bytes
    return msg
