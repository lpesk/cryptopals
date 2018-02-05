from tools.message import Message
from tools.oracle import Oracle
from tools.bitops import XOR
from tools.aes import AES_ECB
from tools.aesattacks import crackEditableCTR

with open('data/set1ch7.txt', 'r') as infile:
    ecb_ciphertext = Message(infile.read(), 'base64')
    ecb_key = Message(b'YELLOW SUBMARINE')
    msg = AES_ECB(ecb_ciphertext, ecb_key, fn='decrypt')

oracle = Oracle()
ciphertext = oracle.encryptCTR(msg)
decryption = crackEditableCTR(ciphertext, oracle.editCTR)
print(decryption.ascii())
