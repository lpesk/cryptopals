#####################################################
######     cryptopals set 2, challenge 9       ######
#####################################################

############# implement pkcs#7 padding  #############

from tools import pad

print repr(pad('YELLOW SUBMARINE', block_size=20))
