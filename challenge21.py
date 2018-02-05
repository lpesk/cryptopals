from tools.mt19937 import mt19937_32
import numpy.random

num_test_vals = 100
num_trials = 1000

# testing that twister produces the same results given the same seed
seed = numpy.random.randint(0, 2**32)
twister = mt19937_32(seed)
first_vals = [twister.next() for i in range(num_test_vals)]

print("Testing that our mt19937-32 implementation produces the same sequence of %d values given the same seed..." % num_test_vals)
for i in range(num_trials):
    test_twister = mt19937_32(seed)
    for j in range(num_test_vals):
        if test_twister.next() != first_vals[j]:
            print("Failed")
            break
print("Successfully completed %d trials" % num_trials)

# testing my twister against numpy's random.randint
seed = numpy.random.randint(0, 2**32)
twister = mt19937_32(seed)
tester = numpy.random.RandomState(seed)

print("Testing that our mt19937-32 implementation gives the same first %d value(s) as numpy.random, given the same seed..." % num_test_vals)
for i in range(num_trials):
    mine = twister.next()
    theirs = tester.randint(0, 2**32)
    if mine != theirs:
        print("Failed")
        break
    print("Successfully completed %d trials" % num_test_vals)

