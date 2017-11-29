#####################################################
######     cryptopals set 3, challenge 24      ######
#####################################################

##### create and break an mt19937 stream cipher #####

import random
from tools import mt19937_CTR, mtOracleFindSeed, mt19937_CTR_Oracle, mtPasswordReset, isTimeSeededMT, newAuthString

seed = random.randint(0, 2**8)
msg = 'yellow submarine'
ctext = mt19937_CTR(msg, seed)

print "plaintext: ", msg 
print "ciphertext: ", repr(ctext)
print "decryption: ", mt19937_CTR(ctext, seed)

print mtOracleFindSeed(mt19937_CTR_Oracle, 'A' * 14, verbose=True)
print mtPasswordReset('hiiiiiiiiiii')

# should be true
print isTimeSeededMT(mtPasswordReset, 'name@domain.com')
# should be false
print isTimeSeededMT(newAuthString, 'name@domain.com')
