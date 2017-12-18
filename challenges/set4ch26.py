#####################################################
######     cryptopals set 4, challenge 26      ######
#####################################################

############# ctr bitflipping attacks ###############

from tools import validateAuthStringCTR, newAuthStringCTR, forgeAuthStringCTR

auth = newAuthStringCTR("\x00"*18)
print auth
print "Am I admin yet?\n", validateAuthStringCTR(auth)

new_auth = forgeAuthStringCTR()
print new_auth
print "Am I admin yet?\n", validateAuthStringCTR(new_auth)


