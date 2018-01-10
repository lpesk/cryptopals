from tools.bitops import XOR, hamDist
from tools.message import Message
from tools.bitops import repXOR
from string import ascii_letters


def scoreText(msg, case=False, space=True):
    """ Given a string, compute a score representing the
    likelihood that the string is English text. Scores are
    floats in range [-1, 1]. A higher score indicates a
    a higher likelihood that input string was English text.
    By default, the function gives higher scores to strings
    with English-like frequency of spaces, and is not case
    sensitive. Both of these defaults can be changed with
    keyword arguments.

    Algorithm: 
        One point is deducted for each character in the 
        string which is not alphabetic or a space. Points
        are awarded for each character which appears both
        among the 6 most frequent characters in the input
        string and also among the 6 most frequent characters
        in typical English, and likewise for the 6 least 
        frequent characters. The number of points awarded 
        for each such character is equal to the length of 
        the string divided by 12 (as a float). Finally, 
        scores are normalized by the length of the string,
        so scores lie in the range [-1, 1]. 
    
    Heuristics:
        Short texts which are not even close to English 
        (e.g., repeating XOR of an English sentence with a
        random key) generally to have negative scores,
        while the positive range seems to disambiguate well
        between short texts which are "almost English" (e.g.,
        the decryption of repeating-key XOR encryptions with 
        a key which differs in a few characters from the true
        key) and perfect English. The optional keyword
        arguments don't seem to make a big difference in
        outcomes, but are occasionally useful for fine-tuning
        once it's clear what kind of text (spaced,
        case-differentiated, etc) we're looking for. 

    Caveats:
        Since the score only depends on character frequency,
        permuting a text doesn't change the score at all,
        and a random sample from an English text (however 
        unlike English it looks) should score about as well
        as the full text. (We'll use this fact to our advantage
        in cryptopals challenge 6!) 

        May not behave as expected on English texts with an
        unusual amount of punctuation, special characters, 
        or whitespace. Probably doesn't differentiate well
        between English and related human languages. 
    
    Args:
        msg (string): the string which is to be scored.
        
        case (boolean): True if priority should be given
        to case-differentiated English text, False to ignore
        case when scoring.

        space (boolean): True if priority should be given
        to text with a frequency of space characters similar
        to that of typical English, False to ignore spaces when
        scoring. 

    Returns:
        float: a score in the range [-1, 1] (including
        endpoints).
    """
    score = 0
    eng_chars = Message(ascii_letters + ' .,;?!-', 'ascii')
    eng_most_freq = set(byt for byt in Message(b'etoai'))
    if space:
        eng_most_freq.add(Message(b' '))
    else:
        eng_most_freq.add(Message(b'n'))
    eng_least_freq = set(byt for byt in Message(b'zqxjkv'))

    counts = { byt: 0 for byt in eng_chars }

    # count alpha chars and spaces
    # decrement score for each nonalpha/space char
    for byt in msg:
        if byt in eng_chars:
            counts[byt] += 1
        else:
            score -= 1
    sort_counts = sorted(counts, key=counts.get, reverse=True)

    # compare 6 highest- and lowest-freq chars in msg to 
    # those in typical english, and increment score for 
    # each char in common in high/low freq bins
    if case:
        msg_most_freq = set(sort_counts[0:6])
        msg_least_freq = set(sort_counts[-6:])
    else: 
        msg_most_freq = set([Message(char.bytes.lower()) for char in sort_counts[0:6]])
        msg_least_freq = set([Message(char.bytes.lower()) for char in sort_counts[-6:]])

    pts_per_char = len(msg) / (len(eng_most_freq) + len(eng_least_freq))
    score += pts_per_char * (len(eng_most_freq & msg_most_freq) + len(eng_least_freq & msg_least_freq))
    normalized_score = score / len(msg)
    return normalized_score

def scanKeys(msg, case=True, space=True, verbose=False):
    """ Scans for the key used to encrypt an English text
    using a single-character XOR cipher. 

    Algorithm:
        Given a string, scans through all ascii characters. For each such 
        character, uses tools.repXOR to compute the XOR 
        of the input string with the key consisting of 
        the character times the length of the input string,
        and scores the result using tools.scoreText.
        Returns a tuple containing the highest observed score
        and the corresponding key and decryption. 

    Args:
        msg (string): a string which is to be tested for 
        the property of being a single-character XOR encryption
        of an English text. 

        msg_format (string): the encoding of the bytes 
        represented by the string 'msg'. Options are 'ascii'
        (default), 'hex', and 'base64'.

        case (boolean): see docstring for tools.scoreText.
        
        space (boolean): see docstring for tools.scoreText.
        
        verbose (boolean): if True, function will print the
        highest-scoring key and decryption; not if False.

    Returns:
        tuple (float, int, string): the first parameter is the
        highest observed score, and the second parameter is  
        the key (as an ascii value in range [32, 127]
        inclusive) which produces a decryption achieving that
        high score. The third parameter is that decryption. 

        Note that only one such tuple is returned, even if
        several keys produce decryptions which achieve the
        highest observed score. (In this case, the tuple
        returned will be the one which comes first in
        alphabetical order.)
    """
    key_data = { }
    for val in range(256):
        key = Message(bytes([val]) * len(msg))
        decryption = XOR(msg, key)
        key_data[key[0]] = (scoreText(decryption, case, space), decryption)
    
    sort_scores = sorted(key_data, key=key_data.get, reverse=True)
    best_key = sort_scores[0]
    best_score, best_decryption = key_data[best_key]

    if verbose:
         print("The best result is:\n\n\tKey:", best_key.ascii())
         print("\tScore:", best_score)
         print("\tDecryption: %s\n" % best_decryption.ascii())
    return best_score, best_key, best_decryption

def guessKeySize(msg, lower=2, upper=41, segments=4, guesses=1, verbose=False):
    """ Given a string and assuming that the string is the 
    encryption of an English text with repeating-key XOR, 
    guess the length of the key. User can specify the range 
    key lengths to test, and the number of guesses to return
    (in order of likelihood).

    Algorithm:
        The algorithm is based on the observation that, on
        average, pairs of strings of English text have a 
        smaller Hamming distance than pairs of random strings.
        Furthermore, XOR'ing both members of a pair of strings
        with the same key preserves their Hamming distance.
        
        Given a possible key length, slice out a small 
        number of segments of that length. The number of 
        segments is specified by the user (with a tradeoff of 
        time vs. accuracy), and the default number is 4. The 
        average Hamming distance of all of the distinct pairs
        of these segments is computed. This computation is 
        repeated for all key lengths within the bounds 
        specified by the user. The key length which produces 
        the smallest average Hamming distance is returned as
        the most likely key length.
        
    Args:
        msg (string): a string which we assume is the
        encryption of an English text with repeating-key
        XOR.

        msg_format (string): the encoding of the bytes
        represented by 'msg'. Options are 'ascii' (default),
        'hex', and 'base64'.

        lower (int): lower bound (inclusive) on the range of
        possible key sizes. Must be at least 1.

        upper (int): upper bound (exclusive) on the range of
        possible key sizes. Must be greater than 'lower'.

        segments (int): the number of segments for which the 
        Hamming distance is compared.

        guesses (int): the number of guesses to return, in
        decreasing order of likelihood. Must be a positive 
        integer less than or equal to ('upper' - 'lower').

        verbose (boolean): if True then a description of the
        output is printed before returning; not if False.

    Returns:
        list of ints: a list, of length is equal to 'guesses',
        of the most likely keys, in decreasing order of
        likelihood. Each key is an integer in range [32, 127]
        inclusive. 
    """
    assert (lower > 0 and upper > lower), "Please enter a valid range of key sizes"
    assert (segments > 1), "Must use at least 2 segments"
    assert (guesses > 0 and upper - lower >= guesses), "Please enter a valid number of guesses"
    assert (len(msg) >= segments * upper), "The message is too short to support this search range and number of segments"
    key_dists = { }
    for i in range(lower, upper):
        key_size = i
        segs = [msg[j * key_size : (j + 1) * key_size] for j in range(segments)]
        # form the set of pairs of distinct integers 
        # (unordered) in range [0, segments)
        pairs = [(j, k) for j in range(segments) for k in range(j)]
        # compute the normalized hamming distance for each pair
        norm_dists = [hamDist(segs[pair[0]], segs[pair[1]]) / key_size for pair in pairs]
        # take the average distance of the pairs
        avg_norm_dist = sum(norm_dists) / len(pairs)
        key_dists[key_size] = avg_norm_dist
    sort_sizes = sorted(key_dists, key=key_dists.get)
    guess_list = sort_sizes[:guesses]
    if verbose:
        if guesses == 1:
            print("The most likely key length is %d.\n" % guess_list[0])
        else:
            print("In decreasing order of likelihood, the %d most likely key lengths are:" % guesses)
            print(', '.join(map(str, guess_list)) + '\n')
    return guess_list

def guessRepXORKey(msg, key_size, case=True, space=True, verbose=False):
    """ Given a string which is assumed to be the encryption 
    of an English text using a repeating-key XOR cipher, and
    given the length of the key, this function guesses the
    most likely key.
    
    Algorithm:
        For each index i less than the length m of the key, 
        the (n * m + i)-th bytes of the input string (where
        n runs over the positive integers until the string is
        exhausted) are collected into a new string. The i-th 
        new string consists of all the bytes of the original
        string which were encrypted by XOR'ing with the i-th
        byte of the repeating key. Each of the m new  strings
        is now treated as a single-character-XOR decryption
        problem, which is solved by calling tools.scanKeys.
        The resulting m single-character keys are then pieced
        together to form the repeating key. 

    Args:
        msg (string): the string which is to be decrypted.
        
        key_size (int): the length of the repeating key.

        msg_format (string): the format in which the bytes
        represented by 'msg' are encoded. Options are 'ascii'
        (default), 'hex', and 'base64'.

        case (boolean): see the docstring for tools.scoreText.

        space (boolean): see the docstring for tools.scoreText.

        verbose (boolean): prints decryption of 'msg' with most
        likely key before returning if True, not if False
        (default).

    Returns:
        string: the repeating-XOR key of length 'key_size'
        which was most likely used to encrypt the input string.
    """
    indices = [[i for i in range(len(msg)) if i % key_size == j] for j in range(key_size)]
    blocks = [Message(b''.join(msg[i].bytes for i in indices[j])) for j in range(key_size)]
    key_chars = [scanKeys(blocks[j], case, space) for j in range(key_size)]
    key = Message(b''.join(char[1].bytes for char in key_chars))
    if verbose:
        print("The best key of length %d is: %s\n" % (key_size, repr(key.ascii())))
        print("The decryption of the message with this key is:\n%s" % repXOR(msg, key).ascii())
    return key

