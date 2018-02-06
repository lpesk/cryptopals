from tools.message import Message, BadPad, InvalidEndian, InvalidFormat, joinBlocks, listBlocks, valid_ends
from tools.randomdata import randBase64, randBin, randHex, randMsg, randPrintableMsg

from hypothesis import given
from hypothesis.strategies import binary, builds, integers, text
from pytest import raises, mark

# for now, constrain testing time by bounding length of test messages
min_msg_len = 0
max_msg_len = 1000

def bdd_integers():
    return integers(min_value=min_msg_len, max_value=max_msg_len)

# test that message encoding in a supported format is the left inverse of message creation from that format

@given(test_bytes=binary())
def test_Message_createDisplayBytes(test_bytes):
    test_msg = Message(test_bytes, 'bytes')
    assert test_msg.bytes == test_bytes

@given(test_ascii=text())
def test_Message_createDisplayAscii(test_ascii):
    test_msg = Message(test_ascii, 'ascii')
    assert test_msg.ascii() == test_ascii

@mark.parametrize('end', valid_ends)
@given(test_base64=builds(randBase64, bdd_integers()))
def test_Message_createDisplayBase64(test_base64, end):
    test_msg = Message(test_base64, 'base64', end)
    assert test_msg.base64(end) == test_base64

@mark.parametrize('end', valid_ends)
@given(test_bin=builds(randBin, bdd_integers()))
def test_Message_createDisplayBin(test_bin, end):
    test_msg = Message(test_bin, 'bin', end)
    assert test_msg.bin(end) == test_bin

@mark.parametrize('end', valid_ends)
@given(test_hex=builds(randHex, bdd_integers()))
def test_Message_createDisplayHex(test_hex, end):
    test_msg = Message(test_hex, 'hex', end)
    assert test_msg.hex(end) == test_hex

@mark.parametrize('end', valid_ends)
@given(test_int=integers())
def test_Message_createDisplayInt(test_int, end):
    if test_int < 0:
        with raises(Exception):
            test_msg = Message(test_int, 'int', end)
    else:
        test_msg = Message(test_int, 'int', end)
        assert test_msg.int(end) == test_int

# test that message encoding in a supported format is the right inverse of message creation from that format
# note that a Message instance can be ascii-encoded only if its bytes are printable values

@given(test_msg=builds(randMsg, bdd_integers()))
def test_Message_displayCreateBytes(test_msg):
    test_bytes = test_msg.bytes
    assert Message(test_bytes) == test_msg

@given(test_msg=builds(randPrintableMsg, bdd_integers()))
def test_Message_displayCreateAscii(test_msg):
    test_ascii = test_msg.ascii()
    assert Message(test_ascii, 'ascii') == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bdd_integers()))
def test_Message_displayCreateBase64(test_msg, end):
    test_base64 = test_msg.base64(end)
    assert Message(test_base64, 'base64', end) == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bdd_integers()))
def test_Message_displayCreateBin(test_msg, end):
    test_bin = test_msg.bin(end)
    assert Message(test_bin, 'bin', end) == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bdd_integers()))
def test_Message_displayCreateHex(test_msg, end):
    test_hex = test_msg.hex(end)
    assert Message(test_hex, 'hex', end) == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bdd_integers()))
def test_Message_displayCreateInt(test_msg, end):
    test_int = test_msg.int(end)
    assert Message(test_int, 'int', end) == test_msg
