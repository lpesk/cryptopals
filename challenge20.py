from tools.message import Message
from tools.aes import AES_CTR
from tools.aesattacks import breakRepNonceCTR
from tools.bitops import XOR
from tools.randomdata import randMsg

rand_key = randMsg(16)

with open('data/set3ch20.txt', 'r') as infile:
    lines = [Message(line.rstrip('\n'), 'base64') for line in infile.readlines()]
    
ciphertexts = [AES_CTR(line, rand_key) for line in lines]
partial_key = breakRepNonceCTR(ciphertexts)

for line in ciphertexts:
    key = partial_key + Message(b'\x00' * (len(line) - len(partial_key)))
    decryption = XOR(line, key)
    print(decryption)
