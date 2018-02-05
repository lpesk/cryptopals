from tools.bitops import XOR
from tools.message import Message

def mtNextWord(word, i):
    word_len = 32
    f = 1812433253
    next_word = (f * ( word ^ (word >> (word_len - 2))) + i) & 0xFFFFFFFF
    return next_word

def mtInitialize(word):
    state_words = 624
    state = [word] + [0] * (state_words - 1)
    for i in range(1, state_words):
        state[i] = (mtNextWord(state[i - 1], i))
    return state

def mtTwist(word):
    a = int('9908B0DF', 16)
    twist = word >> 1
    if word % 2:
        twist = twist ^ a
    return twist

def mtTemper(word):
    U = 11
    S = 7
    T = 15
    L = 18
    B = int('9D2C5680', 16)
    C = int('EFC60000', 16)
    
    x = word ^ (word >> U)
    y = x ^ ((x << S) & B)
    z = y ^ ((y << T) & C)
    tempered = z ^ (z >> L)
    return tempered

class mt19937_32():  
    def __init__(self, seed):
        self.state = mtInitialize(seed)
        self.index = 0
    
    def next(self):
        state = self.state
        index = self.index
        new = state[(index + 397) % 624] ^ (mtTwist((state[index] & 0x80000000) ^ (state[(index + 1) % 624] & 0x7fffffff)))
        self.state[index] = new
        self.index = (index + 1) % 624
        return mtTemper(new)

def mt19937_32_CTR(msg, seed):
    twister = mt19937_32(seed)
    # next key byte is the least significant byte of the next output of twister
    key = Message(b'').join(Message(bytes([twister.next() & 0xFF])) for byt in msg)
    return XOR(key, msg)
    
        
        
