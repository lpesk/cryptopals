from tools.message import Message
from tools.oracle import Oracle
from tools.aesattacks import decryptPostfixECB
from tools.randomdata import randMsg

prefix = randMsg(0, 20)
postfix_str = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
postfix = Message(postfix_str, 'base64')
oracle = Oracle(None, prefix, postfix)

decryption = decryptPostfixECB(oracle.encryptECB)
print(decryption.ascii())

