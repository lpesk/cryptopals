from tools.mt19937 import mt19937_32
from tools.rngattacks import mtCrackTimeSeed
from random import randint
from time import sleep, time

def mtGenerator():
    sleep(randint(40, 1000))
    timestamp = int(time())
    twister = mt19937_32(timestamp)
    sleep(randint(40, 1000))
    return twister.next()

if __name__ == '__main__':
    hour = 3600
    val = mtGenerator()
    now = int(time())

    seed = mtCrackTimeSeed(val, now - hour, now)
    print("First output of MT19937-32 RNG: %d" % val)
    if seed:
        print("Seed: %d" % seed)
    else:
        print("Seed not found in the past %d seconds" % hour)
