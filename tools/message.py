import base64

""" valid_formats: list of valid format options for all 
functions operating on strings.
"""
valid_formats = ['bytes', 'ascii', 'bin', 'hex', 'base64']

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
        msg_bytes = base64.b16decode(bytes(msg, encoding='utf-8'), True)
    else:
        msg_bytes = base64.b64decode(bytes(msg, encoding='utf-8'))
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
        return ''.join(bin(ord(byt)).lstrip('0b').zfill(8) for byt in msg_bytes)
    elif out_format == 'ascii':
        msg = msg_bytes
    elif out_format == 'hex':
        msg = base64.b16encode(msg_bytes).lower()
    else:
        msg = base64.b64encode(msg_bytes)
    return msg.decode('utf-8')
        
class Message():
    def __init__(self, msg, msg_format='bytes', end='big'):
        if msg_format == 'bytes':
            self.bytes = msg
        elif msg_format in valid_formats and end in valid_ends:
            self.bytes = _decode(msg, msg_format, end)
        else:
            raise InvalidFormat

    def __repr__(self):
        return "Message(%s)" % repr(self.bytes)

    def __len__(self):
        return len(self.bytes)

    def __getitem__(self, key):
        if isinstance(key, int):
            return Message(bytes([self.bytes[key]]))
        elif isinstance(key, slice):
            return Message(self.bytes[key])
        else:
            raise Exception

    def __add__(self, other):
        return Message(self.bytes + other.bytes)
    
    def __mul__(self, rep):
        return Message(self.bytes * rep)

    def ascii(self):
        return _encode(self.bytes, 'ascii')

    def bin(self, end='big'):
        return _encode(self.bytes, 'bin', end)

    def hex(self, end='big'):
        return _encode(self.bytes, 'hex', end)

    def base64(self, end='big'):
        return _encode(self.bytes, 'base64', end)
        
    def pad(self, block_size=16, extra=True):
        assert (1 <= block_size and block_size <= 256), "Block size must be an integer in [1, 256] inclusive"
        if len(self) % block_size == 0:
            if extra:
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

def blocks(msg, block_size=16):
    assert (1 <= block_size and block_size < 256), "Block size must be an integer in range(1, 256)"
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
