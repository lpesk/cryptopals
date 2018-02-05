from tools.message import Message
from tools.aes import AES_CBC
from tools.oracle import Oracle
from tools.aesattacks import paddingOracle
from tools.randomdata import randMsg
from random import randint

cookies = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

class CookieFactory(Oracle):
    def __init__(self):
        self.prefix = Message(b'')
        self.postfix = Message(b'')
        self.key = randMsg(16)
    
    def __repr__(self):
        return "A nice cookie factory which checks your padding for you"

    def newCookie(self):
        index = randint(0, len(cookies)-1)
        cookie = Message(cookies[index], 'base64')
        return self.encryptCBC(cookie)

    def isValidCookie(self, msg):
        return self.decryptAndCheckPadCBC(msg)
    

def decryptSeries(factory, cookie_vals, cookie_id_byte, verbatim=True):
    found = [False for _ in range(cookie_vals)] 
    goal = [True for _ in range(cookie_vals)]
    decrypts = [Message(b'') for _ in range(cookie_vals)]
    
    while found != goal:
        cookie = factory.newCookie()
        decryption = paddingOracle(factory.isValidCookie, cookie)
        cookie_val = int(decryption[cookie_id_byte].bytes)
        if not found[cookie_val]:
            found[cookie_val] = True
            decrypts[cookie_val] = decryption
            print("Found cookie", cookie_val)
    print("Putting it all together...\n")
    if not verbatim:
        decrypts = [decrypt.stripPad(strict=False) for decrypt in decrypts]
    series = Message(b'\n'.join(decrypt.bytes for decrypt in decrypts))
    return(series)

if __name__ == '__main__':
    factory = CookieFactory()
    cookie_vals = 10
    cookie_id_byte = 5
    print(decryptSeries(factory, cookie_vals, cookie_id_byte, verbatim=False).ascii())
