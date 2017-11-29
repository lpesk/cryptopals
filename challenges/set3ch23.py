#####################################################
######     cryptopals set 3, challenge 23      ######
#####################################################

##### clone an mt19937 instance from its output  ####

import random
from tools import mt19937, mtClone

NUM_TRIALS = 1000
seed = random.randint(0, 2**32)
twister = mt19937(seed)
clone = mtClone(twister)

print "Testing that first %d outputs match..." % NUM_TRIALS
for i in range(NUM_TRIALS):
    if twister.next() != clone.next():
        print "bad"
        break
print "done!"
