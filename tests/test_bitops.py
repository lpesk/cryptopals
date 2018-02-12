from tools.bitops import XOR, repeatXOR, rotate, hammingDistance
from tools.message import Message
from tools.randomdata import bddIntegers, randMsg

from hypothesis import assume, given
from hypothesis.strategies import builds, integers, text
from pytest import mark, raises

# test that XOR throws an error if inputs are not of equal length
@given(msg1=builds(randMsg, bddIntegers()), msg2=builds(randMsg, bddIntegers()))
def test_XOR_errorIfNotSameLen(msg1, msg2):
    if len(msg1) != len(msg2):
        with raises(AssertionError):
            XOR(msg1, msg2)
    else:
        XOR(msg1, msg2)

# test that XOR is commutative
@given(length=bddIntegers())
def test_XOR_isCommutative(length):
    msg1 = randMsg(length)
    msg2 = randMsg(length)
    assert XOR(msg1, msg2) == XOR(msg2, msg1)

# test that XOR is its own inverse
@given(length=bddIntegers())
def test_XOR_selfInverse(length):
    msg1 = randMsg(length)
    msg2 = randMsg(length)
    assert XOR(msg1, XOR(msg1, msg2)) == msg2

# test that repeatXOR is its own inverse
@given(msg_len=bddIntegers(min_value=1), key_len=bddIntegers(min_value=1))
def test_repeatXOR_selfInverse(msg_len, key_len):
    msg = randMsg(msg_len)
    key = randMsg(key_len)
    assert repeatXOR(repeatXOR(msg, key), key) == msg

# test that rotation to the left is multiplication by 2 if the bit string doesn't wrap around
@given(integer=bddIntegers(min_value=1), total_bits=bddIntegers(min_value=2))
def test_rotate_leftShiftDoubles(integer, total_bits):
    assume (integer < (2 ** (total_bits - 1)))
    assert rotate(integer, 1, total_bits) == 2 * integer

# test that rotations by the same number of bits in opposite directions are inverse
@given(integer=bddIntegers(min_value=1), rotate_bits=bddIntegers(), total_bits=bddIntegers(min_value=1))
def test_rotate_leftRightInverse(integer, rotate_bits, total_bits):
    assume (integer < (2 ** total_bits))
    assume (abs(rotate_bits) < total_bits)
    assert integer == rotate(rotate(integer, rotate_bits, total_bits), (-1) * rotate_bits, total_bits)

# hamming distance example from challenge 6
def test_hammingDistance_example():
    msg1 = Message(b'this is a test')
    msg2 = Message(b'wokka wokka!!!')
    assert hammingDistance(msg1, msg2) == 37

# test that hamming distance is less than or equal to the bit length of the longer of the two messages
@given(msg1=builds(randMsg, bddIntegers()), msg2=builds(randMsg, bddIntegers()))
def test_hammingDistance_bitLengthBound(msg1, msg2):
    max_dist = max(len(msg1.bin()), len(msg2.bin()))
    assert hammingDistance(msg1, msg2) <= max_dist

# test that the hamming distance from a message to itself is 0
@given(msg=builds(randMsg, bddIntegers()))
def test_hammingDistance_selfIsZero(msg):
    assert hammingDistance(msg, msg) == 0

