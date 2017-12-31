
# TODO: test and document
def mtNextWord(word, i):
    word_len = 32
    f = 1812433253
    next_word = (f * ( word ^ (word >> (word_len - 2))) + i) & 0xFFFFFFFF
    return next_word

# TODO: test and document
def mtInitialize(word):
    state_words = 624
    state = [word] + [0] * (state_words - 1)
    for i in range(1, state_words):
        state[i] = (mtNextWord(state[i - 1], i))
    return state

# TODO: test and document
def mtTwist(word):
    '''
    Args:
        word: a 32-bit integer

    Returns:
        twist: a 32-bit integer
    '''
    a = int('9908B0DF', 16)
    twist = word >> 1
    if word % 2:
        twist = twist ^ a
    return twist

# TODO: test and document
def mtTemper(word):
    '''
    Args:
        word: a 32-bit integer

    Returns:
        tempered: a 32-bit integer
    '''
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

# TODO: test and document
def mtUntemper(tempered):
    '''
    Args:
        tempered: a 32-bit integer, assumed to be the output of mtTemper() on some 32-bit input
    
    Returns:
        word: a 32-bit integer which is the preimage of 'tempered' under mtTemper()
    '''
    U = 11
    S = 7
    T = 15
    L = 18
    B = int('9D2C5680', 16)
    C = int('EFC60000', 16)

    z = tempered ^ (tempered >> L)
    y = z ^ ((z << T) & C) ^ ((z << 2*T) & (C << T) & C)
    x = y ^ ((y << S) & B) ^ ((y << 2*S) & (B << S) & B) ^ ((y << 3*S) & (B << 2*S) & (B << S) & B) ^ ((y << 4*S) & (B << 3*S) & (B << 2*S) & (B << S) & B)
    word = x ^ (x >> U) ^ (x >> 2*U)
    return word

class mt19937():  
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
