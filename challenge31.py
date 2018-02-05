from tools.message import Message
from tools.authentication import hmacSHA1
from tools.authattacks import timingAttackHMACSHA1
from tools.message import Message
from tools.randomdata import randMsg
from Crypto.Hash import HMAC as true_HMAC
from Crypto.Hash.SHA import SHA1Hash
from tools.server import Server

"""
TODO: my implementation of HMAC is based on the pseudocode on wikipedia. it does not produce the same results as pycrypto's HMAC-SHA1 (see test below). i'm guessing that pycrypto handles some detail differently, e.g. has a different padding scheme. check out the pycrypto source to confirm this.

trials = 10

for trial in range(trials):
    key = randMsg(0, 300)
    msg = randMsg(0, 1000)
    test_digest = hmacSHA1(key, msg)
    print("\nTest HMAC-SHA1:", test_digest)

    
    h = true_HMAC.new(key.bytes, digestmod=SHA1Hash())
    h.update(msg.bytes)
    true_digest = h.hexdigest()
    print("True HMAC-SHA1:", true_digest)

    assert (test_digest == true_digest)
"""

"""
run tmp_servertest.py before running the following. TODO: timingAttackHMACSHA1 does not reliably distinguish between signal and random variation in response times. consider some different strategies.
"""

ip = '127.0.0.1'
port = 8080
url = 'http://' + ip + ':' + str(port) + '/test'
filename = 'data/challenge31.txt'
print(timingAttackHMACSHA1(url, filename))
