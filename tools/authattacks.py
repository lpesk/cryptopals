from tools.message import Message
from tools.sha1 import SHA1
from tools.md4 import MD4
from tools.authentication import macSHA1, macMD4
from tools.randomdata import randMsg
from requests import get
from time import perf_counter
from pandas import Series
from statistics import mode

def extendMACSHA1(msg, mac, add_msg, key_len):
    state_vars = 5
    state_hex_digs = 8
    state = [Message(mac[k * state_hex_digs: (k + 1) * state_hex_digs], 'hex').int() for k in range(state_vars)]

    s = SHA1()
    orig_msg_pad = s.formPad(len(msg) + key_len)
    new_msg = msg + orig_msg_pad + add_msg
    new_msg_pad = s.formPad(len(new_msg) + key_len)
    
    extended_mac = s.hash(add_msg + new_msg_pad, state, pad=False)
    return (new_msg, extended_mac)

def extendMACMD4(msg, mac, add_msg, key_len):
    state_vars = 4
    state_hex_digs = 8
    state = [Message(mac[k * state_hex_digs: (k + 1) * state_hex_digs], 'hex', 'little').int() for k in range(state_vars)]

    s = MD4()
    orig_msg_pad = s.formPad(len(msg) + key_len)
    new_msg = msg + orig_msg_pad + add_msg
    new_msg_pad = s.formPad(len(new_msg) + key_len)

    extended_mac = s.hash(add_msg + new_msg_pad, state, pad=False)
    return (new_msg, extended_mac)

def collectTimingData(url, filename):
    """ collect data about the timing needed to get the first byte """
#    if partial_sig is None:
#        partial_sig = ''
    
    # get the file we're requesting into the server's cache before we start timing
    query = {'file': filename, 'signature': '00'}
    get(url, params=query)
    
    # 1765 is the number of trials such that for a given byte, we see it at least once with probability > .999
    trials = 1765
    raw_times = [None] * trials
    for trial in range(trials):
        test_byte = randMsg(1).hex()
        query = {'file': filename, 'signature': test_byte}
        time_before = time()
        r = get(url, params=query)
        time_after = time()
        raw_times[trial] = time_after - time_before
    times = Series(raw_times)
    return (times.mean(), times.max(), times.std())

def cacheLoad(url, filename):
    for val in range(256):
        test_byte = hex(val).lstrip('0x').rjust(2, '0')
        query = {'file': filename, 'signature': test_byte}
        get(url, params=query)
    return
    
def timingAttackHMACSHA1(url, filename, partial_sig=None):
    """
    (thing_to_sign, partial_hmac): where thing_to_sign is whatever kind of object (message, filename, etc) the server expects, and partial_hmac could be empty

    try collecting data for 1-2 rounds to see how long it usually takes to decide that the first byte is wrong, then check for cases where it takes ~.05s longer than that to give a negative response. 

    weird thing: for a while, this was often (but not always) getting the incorrect value 'd4' (212 in dec) for the 2nd byte. this persisted after restarting the server with a new key. what's up with that? then also sometimes it'd make it past the 2nd byte but fail often with '7c' as the 3rd byte. is there something about these values (relative to cache sizes or something?) which means that they frequently have longer response times?
    """
    true_sig = '88e9db14f1575a88ff75a06235eaeb5bcbf73e12'
    trials = 10
    # if this is the beginning, make a throwaway request to get the file into the server's cache before we start logging response times
    if partial_sig is None:
        partial_sig = ''
        query = {'file': filename, 'signature': '00'}
        get(url, params=query)
    test_sig = partial_sig

    byte_times = [[] for _ in range(256)]
    for trial in range(trials):
        print("trial %d of %d for byte %d" % (trial + 1, trials, int(len(partial_sig)/2) + 1))
        for val in range(256):
            test_byte = hex(val).lstrip('0x').rjust(2, '0')
            test_sig = partial_sig + test_byte
      
            time_before = perf_counter()
            r = get(url, params={'file': filename, 'signature': test_sig})
            time_after = perf_counter()
            diff = time_after - time_before
        
            byte_times[val].append(diff)
            status = r.status_code
        
            if status == 200:
                print("good sig, good job")
                return test_sig
            if len(test_sig) > 40:
                raise Exception("sorry, didn't work :(")  

#    best_byte = hex(byte_times.index(max(byte_times))).lstrip('0x').rjust(2, '0')
#    partial_sig += best_byte
#    print("sig so far:", partial_sig)
#    if partial_sig != true_sig[:len(partial_sig)]:
#        raise Exception("failed at byte %d" % int(len(partial_sig)/2))
#    return timingAttackHMACSHA1(url, filename, partial_sig)
    for val in range(256):
        byte_times[val].remove(max(byte_times[val]))
        byte_times[val].remove(max(byte_times[val]))
        byte_times[val].remove(max(byte_times[val]))
    byte_total_times = [sum(byte_times[val]) for val in range(256)]
    best_byte = hex(byte_times.index(max(byte_times))).lstrip('0x').rjust(2, '0')
    partial_sig += best_byte
    print("sig so far:", partial_sig)
    if partial_sig != true_sig[:len(partial_sig)]:
        raise Exception("failed at byte %d" % int(len(partial_sig)/2))
    return timingAttackHMACSHA1(url, filename, partial_sig)
    
    
