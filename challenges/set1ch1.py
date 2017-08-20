#####################################################
### matasano crypto challenge set 1, challenge 1 ####
#####################################################

######## convert a hex string to base64 #############

from tools import decode, encode

TEST_IN = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

TEST_OUT = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

out = encode(decode(TEST_IN, 'hex'), 'base64')
assert (out == TEST_OUT), "Test case failed"
print out
