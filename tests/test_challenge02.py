from tools.bitops import XOR
from tools.message import Message

def test_challenge02_example():
    hex_1 = '1c0111001f010100061a024b53535009181c'
    hex_2 = '686974207468652062756c6c277320657965'
    true_xor_hex = '746865206b696420646f6e277420706c6179'

    msg_1 = Message(hex_1, 'hex')
    msg_2 = Message(hex_2, 'hex')
    test_xor_hex = XOR(msg_1, msg_2).hex()

    assert true_xor_hex == test_xor_hex
