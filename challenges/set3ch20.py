#####################################################
######     cryptopals set 3, challenge 20      ######
#####################################################

##### break fixed-nonce AES-CTR statistically  ######

from tools import rand_key, AES_CTR, XOR, guessRepXORKey, breakRepXOR

with open('../data/set3ch20.txt', 'r') as infile:
    lines = infile.readlines()

lines_encr = [AES_CTR(line, rand_key, nonce='0'*16, msg_format='base64', key_format='ascii', nonce_format='hex') for line in lines]
min_len = min([len(line) for line in lines_encr])
ctext=''.join([line[:min_len] for line in lines_encr])

guess_key = guessRepXORKey(ctext, min_len, msg_format='ascii', case=True, space=True)

for i in range(len(lines_encr)):
    print XOR(guess_key, ctext[i*min_len: (i+1)*min_len], 'ascii', 'ascii')
