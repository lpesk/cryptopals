#####################################################
######     cryptopals set 2, challenge 10      ######
#####################################################

########### implement AES in CBC mode  #############

from tools import AES_CBCFile

print AES_CBCFile('../data/set2ch10.txt', 'YELLOW SUBMARINE', '\x00'*16, in_file_format='base64', key_format='ascii', iv_format='ascii', fn='decrypt')
