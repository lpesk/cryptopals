from tools.message import Message, listBlocks, joinBlocks, InvalidFormat, InvalidEndian, BadPad
from tools.randomdata import randBase64, randBin, randHex, randMsg, randPrintableMsg

from hypothesis import given
from hypothesis.strategies import binary, builds, integers, text
from pytest import raises

# for now, constrain testing time by bounding length of test messages
min_msg_len = 0
max_msg_len = 1000

def bdd_integers():
    return integers(min_value=min_msg_len, max_value=max_msg_len)

# test that message encoding in a supported format is the left inverse of message creation from that format
@given(binary())
def test_Message_createDisplayBytes(test_bytes):
    test_msg = Message(test_bytes)
    assert test_msg.bytes == test_bytes

@given(text())
def test_Message_createDisplayAscii(test_ascii):
    test_msg = Message(test_ascii, 'ascii')
    assert test_msg.ascii() == test_ascii

@given(builds(randBase64, bdd_integers()))
def test_Message_createDisplayBase64(test_base64):
    test_msg = Message(test_base64, 'base64')
    assert test_msg.base64() == test_base64

@given(builds(randBin, bdd_integers()))
def test_Message_createDisplayBin(test_bin):
    test_msg = Message(test_bin, 'bin')
    assert test_msg.bin() == test_bin

@given(builds(randHex, bdd_integers()))
def test_Message_createDisplayHex(test_hex):
    test_msg = Message(test_hex, 'hex')
    assert test_msg.hex() == test_hex

@given(integers())
def test_Message_createDisplayInt(test_int):
    if test_int < 0:
        with raises(Exception):
            test_msg = Message(test_int, 'int')
    else:
        test_msg = Message(test_int, 'int')
        assert test_msg.int() == test_int

# test that message encoding in a supported format is the right inverse of message creation from that format
# note that a Message instance can be ascii-encoded only if its bytes are printable values

@given(builds(randMsg, bdd_integers()))
def test_Message_displayCreateBytes(test_msg):
    test_bytes = test_msg.bytes
    assert Message(test_bytes) == test_msg

@given(builds(randPrintableMsg, bdd_integers()))
def test_Message_displayCreateAscii(test_msg):
    test_ascii = test_msg.ascii()
    assert Message(test_ascii, 'ascii') == test_msg

@given(builds(randMsg, bdd_integers()))
def test_Message_displayCreateBase64(test_msg):
    test_base64 = test_msg.base64()
    assert Message(test_base64, 'base64') == test_msg

@given(builds(randMsg, bdd_integers()))
def test_Message_displayCreateBin(test_msg):
    test_bin = test_msg.bin()
    assert Message(test_bin, 'bin') == test_msg

@given(builds(randMsg, bdd_integers()))
def test_Message_displayCreateHex(test_msg):
    test_hex = test_msg.hex()
    assert Message(test_hex, 'hex') == test_msg

@given(builds(randMsg, bdd_integers()))
def test_Message_displayCreateInt(test_msg):
    test_int = test_msg.int()
    assert Message(test_int, 'int') == test_msg
