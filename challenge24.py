from tools.message import Message
from tools.mt19937 import mt19937_32_CTR
from tools.rngattacks import mtResetFindSeed
from tools.oracle import Oracle
from tools.randomdata import randMsg
from random import randint
from time import time

class PasswordReset(Oracle):
    def __init__(self, time_seed=False):
        self.prefix = randMsg(0, 20)
        self.postfix = Message(b'')
        if time_seed == 'coin_flip':
            time_seed = True if randint(0, 1) else False
        if time_seed is True:
            self.key = int(time()) 
        else:
            self.key = randint(0, 2**16 - 1)
        self.time_seed = time_seed
        
    def newResetToken(self, email, test_mode=False):
        email_msg = Message(email, 'ascii')
        token = self.encryptMT19937_32_CTR(email_msg)
        if test_mode:
            return (self.time_seed, self.key, token)
        else:
            return token

if __name__ == '__main__':
    seed = randint(0, 2**16)
    msg = Message(b'yellow submarine')
    ciphertext = mt19937_32_CTR(msg, seed)
    decryption = mt19937_32_CTR(ciphertext, seed)
    
    print("Testing MT19937 stream cipher....\n")
    print("plaintext: ", msg) 
    print("ciphertext: ", ciphertext)
    print("decryption: ", decryption)
    assert(msg == decryption)

    print("\nTesting recovery of seed from random- and time-seeded MT19937-CTR password reset functions...")
    trials = 10
    for trial in range(trials):
        print("\nTrial %d of %d" % (trial + 1, trials))
        reset = PasswordReset(time_seed='coin_flip')
        (is_time_seeded, seed) = mtResetFindSeed(reset.newResetToken, 'A'*14, test_mode=True, verbose=True)
        if seed != None and is_time_seeded != None:
            print("Time-seeded?:", is_time_seeded)
            print("Seed:", seed)
        else:
            print("Failed")
    
    
    



