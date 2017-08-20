#####################################################
######     cryptopals set 1, challenge 7       ######
#####################################################

############ implement AES in ECB mode ##############

from tools import AES_ECBFile

print AES_ECBFile('../data/set1ch7.txt', 'YELLOW SUBMARINE', in_file_format='base64', key_format='ascii', fn='decrypt')
