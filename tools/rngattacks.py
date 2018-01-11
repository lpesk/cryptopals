from tools.mt19937 import mt19937_32

def mtCrackTimeSeed(val, start, end):
    for sec in range(start, end):
        twister = mt19937_32(sec)
        if twister.next() == val:
            return sec
    return None
