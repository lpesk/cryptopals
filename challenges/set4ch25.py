#####################################################
######     cryptopals set 4, challenge 25      ######
#####################################################

###### break random-access read/write aes-ctr #######

from tools import rand_key, AES_ECBFile, AES_CTR, XOR, encode, decode, keyStreamBytesCTR, readBytesCTR, editBytesCTR, editAPI_CTR, crackEditableCTR

ptext = AES_ECBFile('../data/set1ch7.txt', 'YELLOW SUBMARINE', in_file_format='base64', key_format='ascii', fn='decrypt')

ctext = AES_CTR(ptext, rand_key)
print readBytesCTR(ctext, 4, 42, rand_key)

edit = editBytesCTR(ctext, 5, 'hiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii!', rand_key)
print edit
print AES_CTR(edit, rand_key)

edit = editAPI_CTR(ctext, 5, 'hiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii!')
print edit
print crackEditableCTR(ctext)



        
