from tools.mt19937 import mt19937_32
from tools.rngattacks import mtClone
from random import randint

num_test_vals = 1000
seed = randint(0, 2**32)
twister = mt19937_32(seed)
clone = mtClone(twister)

print("Testing that the first %d outputs of cloned RNG match those of the original..." % num_test_vals)
for k in range(num_test_vals):
    if twister.next() != clone.next():
        print("Failed")
        break
print("Success")
