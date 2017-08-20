#####################################################
######     cryptopals set 1, challenge 8       ######
#####################################################

############# detect AES in ECB mode  ###############

from tools import isAES_ECBFile

isAES_ECBFile('../data/set1ch8.txt', file_format='hex', verbose=True)
