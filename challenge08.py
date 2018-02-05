from tools.message import Message
from tools.aesattacks import isAES_ECB

with open('data/set1ch8.txt', 'r') as infile:
    msgs = [Message(line.rstrip('\n'), 'hex') for line in infile.readlines()]

print("Likely encrypted with AES-ECB:")
for msg in msgs:
    if isAES_ECB(msg):
        print("Line", msgs.index(msg))


