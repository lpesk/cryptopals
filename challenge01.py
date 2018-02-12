from tools.message import Message
import pytest

def hexToBase64(msg_hex):
    return Message(msg_hex, 'hex').base64()

if __name__ == '__main__':
    test_hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    true_base64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    test_base64 = hexToBase64(test_hex)

    assert true_base64 == test_base64

    print("\nchallenge 1: convert from hex to base64\n")
    print("{:>7} {}\n{:>7} {}\n".format('hex:', test_hex, 'base64:', test_base64))
