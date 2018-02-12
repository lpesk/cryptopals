from tools.message import BadPad, InvalidEndian, InvalidFormat, joinBlocks, listBlocks, Message, valid_ends
from tools.randomdata import bddIntegers, randBase64, randBin, randHex, randMsg, randPrintableMsg

from hypothesis import given
from hypothesis.strategies import binary, builds, integers, text
from pytest import mark, raises

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
@given(test_base64=builds(randBase64, bddIntegers()))
def test_Message_createDisplayBase64(test_base64, end):
    test_msg = Message(test_base64, 'base64', end)
    assert test_msg.base64(end) == test_base64

@mark.parametrize('end', valid_ends)
@given(test_bin=builds(randBin, bddIntegers()))
def test_Message_createDisplayBin(test_bin, end):
    test_msg = Message(test_bin, 'bin', end)
    assert test_msg.bin(end) == test_bin

@mark.parametrize('end', valid_ends)
@given(test_hex=builds(randHex, bddIntegers()))
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

@given(test_msg=builds(randMsg, bddIntegers()))
def test_Message_displayCreateBytes(test_msg):
    test_bytes = test_msg.bytes
    assert Message(test_bytes) == test_msg

@given(test_msg=builds(randPrintableMsg, bddIntegers()))
def test_Message_displayCreateAscii(test_msg):
    test_ascii = test_msg.ascii()
    assert Message(test_ascii, 'ascii') == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bddIntegers()))
def test_Message_displayCreateBase64(test_msg, end):
    test_base64 = test_msg.base64(end)
    assert Message(test_base64, 'base64', end) == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bddIntegers()))
def test_Message_displayCreateBin(test_msg, end):
    test_bin = test_msg.bin(end)
    assert Message(test_bin, 'bin', end) == test_msg

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bddIntegers()))
def test_Message_displayCreateHex(test_msg, end):
    test_hex = test_msg.hex(end)
    assert Message(test_hex, 'hex', end) == test_msg

# creation of a message from a little-endian int will strip off trailing 0 bytes
# so message creation and encoding as int are not inverse in that case 

@mark.parametrize('end', valid_ends)
@given(test_msg=builds(randMsg, bddIntegers()))
def test_Message_displayCreateInt(test_msg, end):
    test_int = test_msg.int(end)
    if end == 'little':
        test_msg = Message(test_msg.bytes.rstrip(b'\x00'))
    assert Message(test_int, 'int', end) == test_msg

# test that Message.pad produces messages of the correct length

@mark.parametrize('strict', [True, False])
@given(test_msg=builds(randMsg, bddIntegers()), block_size=integers(min_value=1, max_value=255))
def test_Message_padLength(test_msg, block_size, strict):
    orig_msg_len = len(test_msg)
    test_msg.pad(block_size, strict)
    assert len(test_msg) % block_size == 0
    if strict:
        assert orig_msg_len < len(test_msg) and len(test_msg) <= orig_msg_len + block_size
    else:
        assert orig_msg_len <= len(test_msg) and len(test_msg) < orig_msg_len + block_size

# test that Message.stripPad is right inverse to Message.pad

@mark.parametrize('strict', [True, False])
@given(test_msg=builds(randMsg, bddIntegers()), block_size=integers())
def test_Message_padThenStripPad(test_msg, block_size, strict):
    if block_size < 1 or block_size > 255:
        with raises(AssertionError):
            test_msg.pad(block_size, strict).stripPad(block_size, strict)
    elif strict is False and test_msg == Message(b''):
        with raises(AssertionError):
            test_msg.pad(block_size, strict).stripPad(block_size, strict)
    else:
        orig_msg = test_msg
        test_msg.pad(block_size, strict).stripPad(block_size, strict)
        assert orig_msg == test_msg

# test that joinBlocks is right inverse to listBlocks

@given(test_msg=builds(randMsg, bddIntegers()), block_size=integers())
def test_Message_listBlocksThenJoinBlocks(test_msg, block_size):
    if block_size < 1 or block_size > 255:
        with raises(AssertionError):
            listBlocks(test_msg, block_size)
    else:
        joined_msg = joinBlocks(listBlocks(test_msg, block_size))
        assert joined_msg == test_msg
