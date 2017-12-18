
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
    assert (len(msg1.bytes) == len(msg2.bytes)), "Messages must be of equal length"
    xor = Message('', 'bytes')
    xor.bytes = bytearray([msg1_bytes[i] ^ msg2_bytes[i] for i in range(len(msg1_bytes))])
    return xor
    
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
    xor_bits = ''.join(bin(byt)[2:] for byt in xor.bytes())
    # TODO: can use string.count in python 3.4
    dist = sum([int(ch) for ch in xor_bits])
    return dist
