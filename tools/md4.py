from tools.message import Message, listBlocks
from tools.bitops import rotate

class MD4():
    def __init__(self):
        self.state = None

    def formPad(self, msg_len):
        # encode the bit length of msg as a big-endian 8-byte word
        orig_bit_len = msg_len * 8
        orig_len_msg = Message(orig_bit_len, 'int', 'little')
        # TODO: this is only correct for msgs of length < 2 ** 32 so far; see spec
        orig_len_msg_padded = orig_len_msg + Message(b'\x00' * (8 - len(orig_len_msg)))
        
        # add a '1' bit to msg on the less-significant end and fill it out to a byte with '0's
        pad = Message(b'\x80')
        padded_msg_len = msg_len + len(pad)

        # pad with 0 bytes until padded message length is 8 bytes short of a multiple of 64 bytes
        if (padded_msg_len % 64 <= 56):
            pad += Message(b'\x00' * (56 - (padded_msg_len % 64)))
        else:
            pad += Message(b'\x00' * (56 + 64 - (padded_msg_len % 64)))
        
        # add encoding of bit length of the original msg
        # length of padded msg should now be a multiple of 64 bytes
        pad += orig_len_msg_padded
        assert ((msg_len + len(pad)) % 64 == 0)
        return pad

    def processChunk(self, chunk):
        add_lists = lambda x, y: [(x[i] + y[i]) % (2 ** 32) for i in range(len(x))]

        [a, b, c, d] = self.state
        words = [word.int(end='little') for word in listBlocks(chunk, block_size=4)]        

        # round 1
        for i in range(4):
            [a, b, c, d] = round1(a, b, c, d, words[4 * i], 3)
            [d, a, b, c] = round1(d, a, b, c, words[4 * i + 1], 7)
            [c, d, a, b] = round1(c, d, a, b, words[4 * i + 2], 11)
            [b, c, d, a] = round1(b, c, d, a, words[4 * i + 3], 19)
                
        # round 2
        for i in range(4):
            [a, b, c, d] = round2(a, b, c, d, words[i], 3)
            [d, a, b, c] = round2(d, a, b, c, words[i + 4], 5)
            [c, d, a, b] = round2(c, d, a, b, words[i + 8], 9)
            [b, c, d, a] = round2(b, c, d, a, words[i + 12], 13)

        # round 3
        indices = [0, 2, 1, 3]
        for i in range(4):
            index = indices[i]
            [a, b, c, d] = round3(a, b, c, d, words[index], 3)
            [d, a, b, c] = round3(d, a, b, c, words[index + 8], 9)
            [c, d, a, b] = round3(c, d, a, b, words[index + 4], 11)
            [b, c, d, a] = round3(b, c, d, a, words[index + 12], 15)

        self.state = addLists(self.state, [a, b, c, d])

    def formDigest(self):
        [A, B, C, D] = [Message(word, 'int').hex('little').ljust(8, '0') for word in self.state]
        return A + B + C + D

    def hash(self, msg, state=None, pad=True):
        if state is None:
            self.reset()
        else:
            self.state = state
        if pad:
            padded_msg = msg + self.formPad(len(msg))
        else:
            padded_msg = msg
        chunks = listBlocks(padded_msg, block_size=64)
        for chunk in chunks:
            self.processChunk(chunk)
        return self.formDigest()

    def reset(self):
         # i've reversed the bytes in each of the initial constants from the spec
         # because for some reason the spec gives constants in bigendian order
         # and then assumes that all operations are done on littlendian words
         self.state = [0x67452301,
                       0xEFCDAB89,
                       0x98BADCFE,
                       0x10325476]
                      
def addLists(list1, list2):
    assert(len(list1) == len(list2))
    return [(list1[i] + list2[i]) % (2 ** 32) for i in range(len(list1))]
        
def F(X, Y, Z):
    return ((X & Y) | ((0xFFFFFFFF - X) & Z))

def G(X, Y, Z):
    return ((X & Y) | (X & Z) | (Y & Z))

def H(X, Y, Z):
    return (X ^ Y ^ Z)

def round1(W, X, Y, Z, word, rot_bits):
    W = rotate(((W + F(X, Y, Z) + word) % (2 ** 32)), 32, rot_bits)
    return [W, X, Y, Z]

def round2(W, X, Y, Z, word, rot_bits):
    k = 0x5A827999
    W = rotate(((W + G(X, Y, Z) + word + k) % (2 ** 32)), 32, rot_bits)
    return [W, X, Y, Z]

def round3(W, X, Y, Z, word, rot_bits):
    h = 0x6ED9EBA1
    W = rotate(((W + H(X, Y, Z) + word + h) % (2 ** 32)), 32, rot_bits)
    return [W, X, Y, Z]
