#####################################################
######     cryptopals set 4, challenge 27      ######
#####################################################

######## recover key from cbc with iv=key ###########

import sys
from tools import AES_CBC_IVkey, rand_key, verifyAsciiCBC, Unprintable

"""
checking that AES_CBC_IVkey and verifyAsciiCBC work as intended
"""

ctext = AES_CBC_IVkey('yellow submarine', rand_key)
print ctext
print verifyAsciiCBC(ctext, rand_key)

ctext = AES_CBC_IVkey('\x7f', rand_key)
print ctext
print verifyAsciiCBC(ctext, rand_key)

"""
if iv = k (and the iv is omitted from the ciphertext), the AES-CBC decryption of | c1 | 0 | c1 | ... | is :

| D(c1) xor k | D(0) xor c1  | D(c1) | ... |

so, if p1' and p3' are the first and third blocks of the decryption of the modified ciphertext, we have k = p1' xor p3'. 

this decryption won't necessarily have out-of-bounds ascii characters, but it's overwhelmingly likely, since the second and third blocks are essentially random strings drawn from the full ascii range, and only the lower half of the ascii range is in-bounds. 
"""

msg = 'The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it\'s worth).'

ctext = AES_CBC_IVkey(msg, rand_key)
print "original ciphertext:\n", ctext

first_block = ctext[:16]
null_block = '\x00' * 16
new_ctext = first_block + null_block + first_block + ctext[3 * 16:]
print "modified ciphertext:\n", new_ctext

# TODO: look up how to catch and parse the error message from stderr
#new_ptext = capture(verifyAsciiCBC(new_ctext, rand_key))

#key = XOR(new_ptext[:16], new_ctext[2*16:3*16])
#print key

# use the key to decrypt the message:
#ptext = AES_CBC_IVkey(ctext, key)
#print ptext
