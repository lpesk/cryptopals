#####################################################
######     cryptopals set 3, challenge 21      ######
#####################################################

########### implement mersenne twister RNG ##########

import numpy.random as npr
import time
from tools import mt19937

'''
NUM_TEST_VALS = 100
NUM_TRIALS = 1000

# testing that twister produces the same results given the same seed
seed = npr.randint(0, 2**32)
twister = mt19937(seed)
first_vals = [twister.next() for i in range(NUM_TEST_VALS)]

for i in range(NUM_TRIALS):
    test_twister = mt19937(seed)
    for j in range(NUM_TEST_VALS):
        if test_twister.next() != first_vals[j]:
            print "bad"
            break
print "done!"

# testing my twister against numpy's random.randint
seed = npr.randint(0, 2**32)
twister = mt19937(seed)
tester = npr.RandomState(seed)

for i in range(NUM_TRIALS):
    mine = twister.next()
    theirs = tester.randint(0, 2**32)
    print mine, theirs
    if mine != theirs:
        print "bad"
        break
print "done!"
'''
