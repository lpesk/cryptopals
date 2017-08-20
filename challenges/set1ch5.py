#####################################################
######     cryptopals set 1, challenge 5       ######
#####################################################

########## implement repeating-key XOR  #############

from tools import repXOR, encode

print encode(repXOR('Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal', 'ICE'), 'hex')
