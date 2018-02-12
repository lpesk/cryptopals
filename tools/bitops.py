from tools.message import Message

def XOR(msg1, msg2):
    """ Compute the bitwise XOR of two Message instances representing
    equal numbers of bytes.

    Example:
    The bit representation of the byte sequence b'\x01\x02\x03\x04' is:
    |00000001|00000010|00000011|00000100|
    The bit representation of the byte sequence b'\x05\x06\x07\x08' is:
    |00000101|00000110|00000111|00001000|
    Adding modulo 2 without carrying to find the bit representation of the XOR of these two sequences, we get:
    |00000100|00000100|00000100|00001100|
    The byte representation of this sequence is:
    b'\x04\x04\x04\x0c'

    >>> msg1 = Message(b'\x01\x02\x03\x04')
    >>> msg2 = Message(b'\x05\x06\x07\x08')
    >>> XOR(msg1, msg2)
    Message(b'\x04\x04\x04\x0c')

    Args:
        msg1 (Message): one of the two messages to be XOR'd.
        
        msg2 (Message): the other message to be XOR'd.

    Returns:
        Message: instance of class Message containing the bitwise 
        XOR of the bytes represented by 'msg1' and 'msg2'
        respectively.

    Raises:
        AssertionError, "Messages must be of equal length":
        if 'msg1.bytes' and 'msg2.bytes' do not have equal
        length.
    """
    assert (len(msg1) == len(msg2)), "Messages must be of equal length"
    bytes_1 = msg1.bytes
    bytes_2 = msg2.bytes
    xor_bytes = b''.join(bytes([a ^ b]) for (a, b) in zip(bytes_1, bytes_2))
    return Message(xor_bytes)
    
def repeatXOR(msg, key):
    """ Compute the XOR of a message with a repeating key. That is, repeat the key until it reaches the length of the message (if the key is shorter than the message), or truncate the key to the length of the message (if the key is longer than the message), and XOR the result with the message.

    Args:
        msg (Message): the message. The length of this argument determines the length of the output. Must have positive length.
        
        key (Message): the repeating key. Must have positive length.

    Returns:
        Message: the XOR of 'msg' with the repeated (or truncated) 'key'.

    Raises:
        AssertionError, "Message must contain at least 1 byte": if 'msg' is the empty message.
        AssertionError, "Key must contain at least 1 byte": if 'key' is the empty message.
    """
    assert (len(msg) > 0), "Message must contain at least 1 byte"
    assert (len(key) > 0), "Key must contain at least 1 byte"
    key_rem = key[0:(len(msg) % len(key))]
    key_rep = key * int(len(msg)/len(key)) + key_rem
    return XOR(msg, key_rep)

def rotate(integer, rotate_bits, total_bits=32):
    """ Given a positive integer, rotate its bit representation by a specified number of steps to the left or right, wrapping around after a specified number of bits. 

    Example:
    The bit representation of the decimal integer 25 is '11001'. Suppose we want to rotate left and wrap around a width of 8 bits. Rotating 1 bit to the left, we get:
    '110010'
    or, as a decimal integer, 50. If instead we rotate 6 bits to the left and wrap around, we get:
    '1001100'
    or the decimal integer 70. If instead we rotate 6 bits to the right and wrap around, we get:
    '1100100'
    or the decimal integer 100.
    
    >>> rotate(25, rotate_bits=1, total_bits=8)
    50
    >>> rotate(25, rotate_bits=6, total_bits=8)
    70
    >>> rotate(25, rotate_bits=-6, total_bits=8)
    100

    Args:
        integer (int): a positive integer representing the bit string to be rotated.

        rotate_bits (int): the number of bit positions by which to rotate 'integer'. If positive, rotate to the left; if negative rotate to the right; if 0, do nothing.

        total_bits (int): the bit width after which the rotation should wrap around. Must be a positive integer which is greater than or equal to the bit length of 'integer'.

    Returns:
        int: the positive integer representing the rotation of 'integer'.

    Raises:
        AssertionError, "Argument 'integer' must be a positive integer": if 'int' < 0
        AssertionError, "Argument 'total_bits' must be a positive integer": if 'total_bits' < 0
        AssertionError, "Absolute value of 'rotate_bits' must be less than 'total_bits'"
        AssertionError, "Bit length of 'integer' exceeds 'total_bits'": if 'int' > (2 ** total_bits - 1)
    """
    assert (integer > 0), "Argument 'integer' must be a positive integer"
    assert (total_bits > 0), "Argument 'total_bits' must be a positive integer"
    assert (abs(rotate_bits) < total_bits), "Absolute value of 'rotate_bits' must be less than 'total_bits'"
    mask = (2 ** total_bits - 1)
    assert (integer <= mask), "Bit length of 'integer' exceeds 'total_bits'"
   
    if rotate_bits == 0:
        return integer
    # if rotate_bits is positive, rotate left; if negative, rotate right
    elif rotate_bits > 0:
        rotated = ((integer << rotate_bits) | (integer >> (total_bits - rotate_bits))) & mask
    else:
        rotate_bits = abs(rotate_bits)
        rotated = ((integer >> rotate_bits) | (integer << (total_bits - rotate_bits))) & mask
    return rotated

def hammingDistance(msg1, msg2):
    """ Compute the Hamming distance between the byte arrays represented by two Message instances.

    If the two messages are not of equal byte length, then the shorter message is padded with zero bytes (on the high-order side) to the length of the longer message. 

    Args:
        msg1 (Message): one of the two messages to be compared.

        msg2 (Message): the other message to be compared.
        
    Returns:
        int: the number of places at which the bit values of the byte arrays represented by 'msg1' and 'msg2'. Always a nonnegative integer. 
    """
    if len(msg1) < len(msg2):
        msg1 = Message(b'\x00' * (len(msg2) - len(msg1))) + msg1
    elif len(msg2) < len(msg1):
        msg2 = Message(b'\x00' * (len(msg1) - len(msg2))) + msg2

    xor = XOR(msg1, msg2)
    dist = sum(int(bit) for bit in xor.bin())
    return dist

