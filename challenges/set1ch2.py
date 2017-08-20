#####################################################
######     cryptopals set 1, challenge 2       ######
#####################################################

#### bitwise XOR of two equal-length hex strings ####

from tools import XOR, encode

TEST_IN_1 = '1c0111001f010100061a024b53535009181c'

TEST_IN_2 = '686974207468652062756c6c277320657965'

TEST_OUT = '746865206b696420646f6e277420706c6179'

out = encode(XOR(TEST_IN_1, TEST_IN_2, 'hex', 'hex'), 'hex')
assert (out == TEST_OUT), "Test case failed"
print out
