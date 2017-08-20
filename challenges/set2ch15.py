#####################################################
######     cryptopals set 2, challenge 15      ######
#####################################################

######## PKCS#7 padding violation detector  #########

from tools import stripPad

print "Valid padding:\n"
print repr("stripPad(\'ICE ICE BABY\x04\x04\x04\x04\'): "), stripPad('ICE ICE BABY\x04\x04\x04\x04')

print "\nInvalid padding:\n"
print repr("stripPad(\'ICE ICE BABY\x05\x05\x05\x05\'): "), stripPad('ICE ICE BABY\x05\x05\x05\x05')
