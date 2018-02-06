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
    """ Convert a ascii-, binary-, hex-, or base64-encoded
    string into a byte string.

    Args:
        msg (string): a string representing a series
        of bytes in either ascii, hex, or base64 
        encoding.

        msg_format (string): the encoding of the bytes
        represented by 'msg'. Options are 'bytes', 'ascii',
        'bin', 'hex', and 'base64'.

    Returns:
    # TODO: is this definitely a bytes and not a bytearray?
        bytes: a byte string containing the bytes
        represented by 'msg'. 

    Raises:
        InvalidFormat: if 'msg_format' is nonempty 
        and not in 'valid_formats'.
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
    """ Convert a byte array into an ascii-, binary-, hex-, or 
    base64-encoded string.

    Args:
        msg_bytes (bytes): the byte array to be
        converted.

        out_format (string): the desired encoding of
        the bytes of 'msg_bytes' in the output string. 
        Options are 'ascii', 'bin', hex', and 
        'base64'.

    Returns:
        string: string representing the bytes of 
        'msg_bytes', with encoding 'out_format'. 
 
    Raises:
        InvalidFormat: if 'msg_format' is nonempty 
        and not equal to 'ascii', 'bin', 'hex', or 'base64'. 
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
        try:
            self.stripPad()
            return True
        except BadPad:
            return False        

    def validateAscii(self):
        for byt in self.bytes:
            if byt >= 127:
                return False
        return True
        
    def eatChars(self, char_list):
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
        for msg_byt in char_list:
            self.bytes = self.bytes.replace(msg_byt.bytes, b'')
        return self
    
def listBlocks(msg, block_size=16):
    assert (0 < block_size and block_size < 256), "Block size must be an integer in range [1, 255] inclusive"
    num_blocks = int(len(msg)/block_size)
    blocks = [Message(msg.bytes[block_size * i: block_size * (i+1)]) for i in range(num_blocks)]
    if len(msg) % block_size != 0:
        blocks.append(Message(msg.bytes[block_size * num_blocks:]))
    return blocks

def joinBlocks(msg_blocks):
    msg = Message(b'')
    for block in msg_blocks:
        msg.bytes += block.bytes
    return msg
