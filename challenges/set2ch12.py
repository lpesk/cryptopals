#####################################################
######     cryptopals set 2, challenge 12      ######
#####################################################

## byte-at-a-time ecb decryption (simple version) ###

from tools import ECBOracle, findBlockSize, isUsingAES_ECB, decryptPostfixECB

print decryptPostfixECB(ECBOracle, verbose=False)

