from tools.message import Message

def XOR(msg1, msg2):
    """ Compute the bitwise XOR of two strings representing
    equal numbers of bytes.

    Args:
        msg1 (Message): one of the two strings to be XOR'd.
        
        msg2 (Message): the other string to be XOR'd.

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
    xor = Message(b''.join(bytes([a ^ b]) for (a, b) in zip(msg1.bytes, msg2.bytes)))
    return xor
    
def repXOR(msg, key):
    assert(len(key) > 0), "Key must contain at least 1 byte"
    key_rem = key[0:(len(msg) % len(key))]
    key_rep = key * int(len(msg)/len(key)) + key_rem
    return XOR(msg, key_rep)

def rotate(integer, tot_bits, rot_bits):
    # if rot_bits is positive, rotate left; if negative, rotate right
    if rot_bits == 0:
        return integer
    mask = (2 ** tot_bits - 1)
    assert (integer <= mask)
    if rot_bits > 0:
        rotated = ((integer << rot_bits) | (integer >> (tot_bits - rot_bits))) & mask
    else:
        rot_bits = abs(rot_bits)
        rotated = ((integer >> rot_bits) | (integer << (tot_bits - rot_bits))) & mask
    return rotated

def hamDist(msg1, msg2):
    """ Compute the Hamming distance between the byte arrays 
    represented by two Message instances.

    Args:
        msg1 (Message): one of the two messages to be compared.

        msg2 (Message): the other message to be compared.
        
    Returns:
        int: the number of places at which the bit values
        of the byte arrays represented by 'msg1' and 'msg2'.
        Always returns a nonnegative integer. 
    """
    xor = XOR(msg1, msg2)
    dist = sum(int(bit) for bit in xor.bin())
    return dist

