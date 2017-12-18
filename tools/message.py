import base64

""" valid_formats: list of valid format options for all 
functions operating on strings.
"""
valid_formats = ['bytearray', 'ascii', 'bin', 'hex', 'base64']

class InvalidFormat(Exception):
    """ Exception raised when an invalid string is
    passed as a format name.
    """
    def __init__(self):
        Exception.__init__(self, """Invalid format option. Valid options are 'bytearray', 'ascii', 'bin', hex', and 'base64'.""")

def decode(msg, msg_format):
    """ Convert a ascii-, binary-, hex-, or base64-encoded
    string into a byte array. 

    Args:
        msg (string): a string representing a series
        of bytes in either ascii, binary, hex, or base64 
        encoding.

        msg_format (string): the encoding of the bytes
        represented by 'msg'. Options are 'ascii', 'bin',
        'hex', and 'base64'.

    Returns:
        bytearray: a bytearray containing the bytes
        represented by 'msg'. 

    Raises:
        InvalidFormat: if 'msg_format' is nonempty 
        and not equal to 'bytearray', 'ascii', 'bin',
        'hex', or 'base64'. 
    """
    if msg_format not in valid_formats:
        raise InvalidFormat
    if msg_format == 'bytearray':
        msg_bytes = msg
    elif msg_format == 'ascii':
        msg_bytes = bytearray(msg)
    elif msg_format == 'binary':
        # TODO: add binary
        print "TODO: BINARY NOT IMPLEMENTED YET"
        raise InvalidFormat
    elif msg_format == 'hex':
        msg_bytes = bytearray(base64.b16decode(msg, True))
    else:
        msg_bytes = bytearray(base64.b64decode(msg))
    return msg_bytes

def encode(msg_bytes, out_format):
    """ Convert a byte array into an ascii-, binary-, hex-, or 
    base64-encoded string.

    Args:
        msg_bytes (bytearray): the byte array to be
        converted.

        out_format (string): the desired encoding of
        the bytes of 'msg_bytes' in the output string. 
        Options are 'ascii', 'binary', 'hex', and 
        'base64'.

    Returns:
        string: string representing the bytes of 
        'msg_bytes', with encoding 'out_format'. 
 
    Raises:
        InvalidFormat: if 'msg_format' is nonempty 
        and not equal to 'ascii', 'bin', hex', or 'base64'. 
    """
    if out_format not in valid_formats or out_format == 'bytearray':
        raise InvalidFormat
    if out_format == 'ascii':
        msg = str(msg_bytes)
    elif out_format == 'hex':
        msg = base64.b16encode(msg_bytes).lower()
    else:
        msg = base64.b64encode(msg_bytes)
    return msg

# TODO: add a function for properly padded little-endian hex (see decToLitEndHex in tools.py)
class Message():
    def __init__(self, msg, msg_format):
        if msg_format == 'bytes':
            self.bytes = msg
        elif msg_format in valid_formats:
            self.bytes = decode(msg, msg_format)
        else:
            raise InvalidFormat

    def ascii(self):
        return encode(self.bytes, 'ascii')

    def hex(self):
        return encode(self.bytes, 'hex')

    def base64(self):
        return encode(self.bytes, 'base64')

a = Message('hi', 'ascii')
print a.bytes
print a.ascii()
print a.hex()
print a.base64()
