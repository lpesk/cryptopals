from challenges.tools import mt19937
import numpy.random as npr

def test_mt(num_trials=100):
    seed = npr.randint(0, 2**32)
    twister = mt19937(seed)
    tester = npr.RandomState(seed)

    for i in range(num_trials):
        mine = twister.next()
        theirs = tester.randint(0, 2**32)
        assert mine == theirs
