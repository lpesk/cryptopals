from tools.message import Message, listBlocks
from tools.bitops import XOR, rotate

class SHA1():
    def __init__(self):
        self.state = None

    def formPad(self, msg_len):
        # encode the bit length of msg as a big-endian 8-byte word
        orig_bit_len = msg_len * 8
        orig_len_msg = Message(orig_bit_len, 'int')
        orig_len_msg_padded = Message(b'\x00' * (8 - len(orig_len_msg))) + orig_len_msg

        # add a '1' bit to msg on the less-significant end and fill it out to a byte with 0s
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
        # lazy little function to add lists of equal length entrywise (mod 2 ** 32)
        add_lists = lambda x, y: [(x[i] + y[i]) % (2 ** 32) for i in range(len(x))]

        # copy the current state of the instance
        [a, b, c, d, e] = self.state

        # divide the 64-byte chunk into 16 4-byte words
        words = [word.int() for word in listBlocks(chunk, block_size=4)]
        assert (len(words) == 16)

        # extend the list of 16 4-byte words to a list of 80 4-byte words
        for i in range(16, 80):
            next_word = rotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], tot_bits=32, rot_bits=1)
            words.append(next_word)
        assert(len(words) == 80)

        # transform state variables using the sequence of 80 4-byte words
        for i in range(80):
            if i < 20:
                f = ((b & c) | ((0xFFFFFFFF - b) & d))
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            tmp = (rotate(a, tot_bits=32, rot_bits=5) + f + e + k + words[i]) % (2 ** 32)
            e = d
            d = c
            c = rotate(b, tot_bits=32, rot_bits=30)
            b = a
            a = tmp

        # update state
        self.state = add_lists(self.state, [a, b, c, d, e])

    def formDigest(self):
        # concatenate the 5 4-byte state words to form a 20-byte digest
        [a, b, c, d, e] = self.state
        output = (a << 128) | (b << 96) | (c << 64) | (d << 32) | e
        raw_hex = hex(output).lstrip('0x')
        if len(raw_hex) % 2:
            return '0' + raw_hex
        else:
            return raw_hex
            
    def hash(self, msg, state=None, pad=True):
        if state is None:
            self.reset()
        else:
            self.state = state
        if pad:
            padded_msg = msg + self.formPad(len(msg))
        else:
            padded_msg = msg
        assert (len(padded_msg) % 64 == 0)
        chunks = listBlocks(padded_msg, block_size=64)
        for chunk in chunks:
            self.processChunk(chunk)
        return self.formDigest()
 
    def reset(self):
        self.state = [0x67452301,
                     0xEFCDAB89,
                     0x98BADCFE,
                     0x10325476,
                     0xC3D2E1F0]
