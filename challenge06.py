from tools.message import Message
from tools.freqanalysis import guessKeySize, guessRepXORKey
import cProfile

with open('data/set1ch6.txt', 'r') as infile:
    msg = Message(infile.read(), 'base64')

key_size = guessKeySize(msg, verbose=True)[0]
guessRepXORKey(msg, key_size, verbose=True)
