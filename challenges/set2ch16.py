#####################################################
######     cryptopals set 2, challenge 16      ######
#####################################################

############ CBC bitflipping attacks  ###############

from tools import forgeAuthStringCBC

# TODO: implement a function to create unencrypted
# auth strings, to demonstrate that one can't just
# enter an admin token directly. 

print "Am I admin yet?\n"
print "forgeAuthStringCBC(verbose=True): ", forgeAuthString(verbose=True)

