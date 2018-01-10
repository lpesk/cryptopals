from tools.message import Message
from tools.aes import AES_CTR

in_str = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
key_str = 'YELLOW SUBMARINE'

ciphertext = Message(in_str, 'base64')
key = Message(key_str, 'ascii')
plaintext = AES_CTR(ciphertext, key)
print(plaintext.ascii())

re_encrypt = AES_CTR(plaintext, key)
assert (ciphertext == re_encrypt)
