#####################################################
######     cryptopals set 2, challenge 13      ######
#####################################################

############### ECB cut-and-paste  ##################

from tools import parseProfile, newProfile, newEncrProfile, validateProfile, forgeAdminProfile

print "Make a new profile with email address \'abc@def.com\':\n"
profile = newProfile('abc@def.com')
print '\t', profile

print "\nYou can't cheat and put metacharacters in your address:\n"
print '\t', newProfile('abc&xyz@def=mno.com')

print "\n...and here's the encryption of that \'abc@def.com\' profile:\n"
ciphertext = newEncrProfile('abc@def.com')
print '\t', ciphertext

print "\nIt gets validated as a user profile, as it should:\n"
print "validateProfile(ciphertext, verbose=True): ", validateProfile(ciphertext, verbose=True)

print "\n...but we can cut and paste ciphertexts to forge an admin profile!\n"
print "forgeAdminProfile(): ", forgeAdminProfile()
