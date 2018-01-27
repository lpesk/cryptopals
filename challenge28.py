from tools.message import Message
from tools.randomdata import randMsg
from tools.sha1 import SHA1
from tools.authentication import macSHA1
from Crypto.Hash.SHA import SHA1Hash as true_SHA1

# test sha1 implementation against pycrypto's sha1
trials = 10

for trial in range(trials):
    m = randMsg(0, 1000)

    print("\nTrial %d of %d:" % (trial + 1, trials))
    print("\nTesting sha1 hash of ", m)

    test_digest = SHA1().hash(m)
    print("Test digest:", test_digest)

    s = true_SHA1()
    s.update(m.bytes)
    true_digest = s.hexdigest()
    print("True digest:", true_digest)

    assert(test_digest == true_digest)

# demonstrate implementation of sha1 keyed mac
key = randMsg(16)
msg = randMsg(20)
mac = macSHA1(key, msg)
print("\nA sample use of a SHA1 keyed MAC:")
print("Key:", key)
print("Msg:", msg)
print("MAC:", mac)
