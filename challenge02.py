from tools.message import Message
from tools.bitops import XOR

in_str1 = '1c0111001f010100061a024b53535009181c'
in_str2 = '686974207468652062756c6c277320657965'
out_str = '746865206b696420646f6e277420706c6179'

msg1 = Message(in_str1, 'hex')
msg2 = Message(in_str2, 'hex')
xor_str = XOR(msg1, msg2).hex()

assert (xor_str == out_str) 
