# cryptopals
python 3 solutions to the cryptopals challenges: https://cryptopals.com/

These solutions are in progress. (In particular, some docstrings need to be updated and more tests need to be written.) 

A few features of this solution set:
* Rather than operating on raw bytes, most functions operate on instances of a wrapper class, Message (implemented in tools/message.py). Message instances can be created from byte strings, a variety of kinds of encoded strings (ascii, base64, hex, etc) of either endianness, or from positive integers. The main purpose of the wrapper class is to ease conversions between different encodings of byte sequences. Some other convenient features are implemented as special and class methods, e.g. slicing which returns another Message instance, and support for PKCS#7 padding.

* An Oracle class handles encryptions and decryptions (using various choices of encryption scheme) of Message instances under a secret key. A Token class (de)serializes structured data. Together, these two classes form the basis of most of the toy applications which appear in the challenges. 

* The SHA1 and MD4 hash functions are implemented from scratch.

* Tests are property-based wherever possible, and written using the (awesome) Hypothesis library. 
