#####################################################
######     cryptopals set 3, challenge 18      ######
#####################################################

################# implement aes-ctr  ################

from tools import *

TEST_IN_1 = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

TEST_IN_2 = 'Alice attends a trial in which the Knave of Hearts is accused of stealing the Queen\'s tarts. The jury is composed of various animals, including Bill the Lizard; the White Rabbit is the court\'s trumpeter; and the judge is the King of Hearts. During the proceedings, Alice finds that she is steadily growing larger. The dormouse scolds Alice and tells her she has no right to grow at such a rapid pace and take up all the air. Alice scoffs and calls the dormouse\'s accusation ridiculous because everyone grows and she cannot help it. Meanwhile, witnesses at the trial include the Hatter, who displeases and frustrates the King through his indirect answers to the questioning, and the Duchess\'s cook.'

print AES_CTR(TEST_IN_1, 'YELLOW SUBMARINE', msg_format='base64')

ctext = AES_CTR(TEST_IN_2, '\x00'*16, msg_format='ascii')
print ctext

ptext = AES_CTR(ctext, '\x00'*16, msg_format='ascii')
print ptext
