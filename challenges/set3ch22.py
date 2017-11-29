#####################################################
######     cryptopals set 3, challenge 22      ######
#####################################################

############## crack an mt19937 seed  ###############

import time
from tools import mt19937, mtGenerator, mtCrackSeed

'''
if solving this challenge exactly as specified in the problem statement, a range of 1 hour suffices. doesn't take too long (~1 minute) to run with a range of 1 day.
'''

val = mtGenerator()
print "Output of Mersenne Twister: ", val

HOUR = 3600
NOW = int(time.time())

print "Seed: ", mtCrackSeed(3800576579, NOW - HOUR, NOW)
