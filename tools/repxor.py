from bit_operations import XOR

def repXOR(msg, key):
    assert(len(key) > 0), "Key must contain at least 1 byte"
    key_rem = key[0:(len(msg) % len(key))]
    key_rep = key * int(len(msg)/len(key)) + key_rem
    return XOR(msg, key_rep)
