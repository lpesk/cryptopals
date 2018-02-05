from tools.message import Message
from tools.aes import AES_ECB

key_str = 'YELLOW SUBMARINE'
key = Message(key_str, 'ascii')

with open('data/set1ch7.txt', 'r') as infile:
    msg = Message(infile.read(), 'base64')

decryption = AES_ECB(msg, key, fn='decrypt')
print(decryption.ascii())
