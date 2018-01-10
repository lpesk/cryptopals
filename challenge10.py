from tools.message import Message
from tools.aes import AES_CBC

key = Message('YELLOW SUBMARINE', 'ascii')
iv = Message(b'\x00' * 16)

with open('data/set2ch10.txt', 'r') as infile:
    msg = Message(infile.read(), 'base64')

decryption = AES_CBC(msg, key, iv, fn='decrypt')
print(decryption.ascii())
