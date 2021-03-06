from challenge01 import hexToBase64
from tools.message import Message
from tools.randomdata import bddIntegers, randHex

from base64 import b16decode, b64encode
from hypothesis import given
from hypothesis.strategies import builds, integers

def test_challenge01_example():
    test_hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    true_base64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert hexToBase64(test_hex) == true_base64

@given(test_hex=builds(randHex, bddIntegers()))
def test_challenge01(test_hex):
    true_base64 = b64encode(b16decode(bytes(test_hex, 'utf-8'), True)).decode('utf-8')
    test_base64 = hexToBase64(test_hex)
    assert true_base64 == test_base64
    
