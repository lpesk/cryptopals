#####################################################
######     cryptopals set 2, challenge 11      ######
#####################################################

#### implement AES-ECB/CBC oracle and detector  #####

from tools import encrOracle, isUsingAES_ECB, test_isUsingAES_ECB

print "Is the oracle using ECB? 5 trials:\n"
for k in range(5):
    print isUsingAES_ECB(encrOracle)

print "\nIs our distinguisher correct on the next trial?\n"
isUsingAES_ECB(encrOracle, test_mode=True, verbose=True)

print "\nHow many times out of 1000 is our distinguisher correct?\n"
test_isUsingAES_ECB(encrOracle, block_size=16, trials=1000, verbose=True)
