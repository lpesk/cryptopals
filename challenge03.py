from tools.message import Message
from tools.freqanalysis import scanKeys

in_str = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

ciphertext = Message(in_str, 'hex')
scanKeys(ciphertext, case=True, space=True, verbose=True)
