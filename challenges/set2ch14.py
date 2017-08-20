#####################################################
######     cryptopals set 2, challenge 14      ######
#####################################################

###### byte-at-a-time ECB decryption (harder)  ######

from tools import ECBOraclePlus, decryptPostfixECB
  
print decryptPostfixECB(ECBOraclePlus, verbose=False)



