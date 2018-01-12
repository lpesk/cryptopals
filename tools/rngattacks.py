from tools.mt19937 import mt19937_32
from tools.message import Message
from tools.bitops import XOR
from time import time

def mtUntemper(tempered):
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

def mtCrackTimeSeed(val, start, end):
    for sec in range(start, end):
        twister = mt19937_32(sec)
        if twister.next() == val:
            return sec
    return None

def mtClone(twister):
    state = [mtUntemper(twister.next()) for i in range(624)]
    clone = mt19937_32(0)
    clone.state = state 
    return clone

def mtResetFindSeed(reset_fn, user_input, test_mode=False, verbose=False):
    now = int(time())
    hour = 3600
    if test_mode:
        (time_seed, seed, ciphertext) = reset_fn(user_input, test_mode=True)
    else:
        ciphertext = reset_fn(user_input, test_mode=False)
    user_msg = Message(user_input, 'ascii')
    known_len = len(user_msg)
    prefix_len = len(ciphertext) - known_len
    known_ctext = ciphertext[prefix_len:]
    known_keystream = XOR(user_msg, known_ctext)

    if verbose:
        print("Password reset token:", ciphertext)
        print("Prefix length:", prefix_len)
        print("Known slice of keystream:", known_keystream)

    guess_rand_seed = mtCTRCheckSeedRange(known_keystream, prefix_len, 0, 2**16 - 1)
    if guess_rand_seed:
        if test_mode:
            assert(seed == guess_rand_seed and time_seed is False)
        return (False, guess_rand_seed)
    guess_time_seed = mtCTRCheckSeedRange(known_keystream, prefix_len, now - hour, now + 1)
    if guess_time_seed:
        if test_mode:
            assert(seed == guess_time_seed and time_seed is True)
        return (True, guess_time_seed)
    if test_mode:
        return (None, None)
    else:
        return None
        
def mtCTRCheckSeedRange(keystream, prefix_len, min_seed, max_seed):
    for test_seed in range(min_seed, max_seed):
        twister = mt19937_32(test_seed)
        for _ in range(prefix_len):
            twister.next()
        for k in range(len(keystream)):
            test_byte = (twister.next() & 0xFF)
            if bytes([test_byte]) != keystream[k].bytes:
                break
            if k == len(keystream) - 1:
                return test_seed
    return None
