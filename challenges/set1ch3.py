#####################################################
######     cryptopals set 1, challenge 3       ######
#####################################################

############ single-byte xor cipher  ################

from tools import scanKeys, decode

TEST_IN = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736' 
print scanKeys(TEST_IN, msg_format='hex', verbose='v')

