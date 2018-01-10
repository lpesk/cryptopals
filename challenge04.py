from tools.message import Message
from tools.freqanalysis import scanKeys
from collections import namedtuple

min_score = -1

with open('data/tmp_set1ch4.txt', 'r') as infile:
    lines = [Message(line.rstrip('\n'), 'hex') for line in infile.readlines()]

score_data = namedtuple('score_data', 'line_num score key decryption')    
max_score_data = score_data(line_num=None, score=min_score, key=None, decryption=None)
for line in lines:
    (score, key, decryption) = scanKeys(line)
    print(lines.index(line), score, key, decryption)
    if score > max_score_data.score:
        max_score_data = score_data(lines.index(line), score, key, decryption)
print("Line %d was probably encrypted under single-key XOR with key %s" % (max_score_data.line_num, max_score_data.key))
print("The decryption of line %d with this key is:\n%s" % (max_score_data.line_num, max_score_data.decryption))
