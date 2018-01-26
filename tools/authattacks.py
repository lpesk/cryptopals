from tools.message import Message
from tools.sha1 import SHA1
from tools.authentication import macSHA1

def extendMACSHA1(msg, mac, add_msg, key_len):
    state_vars = 5
    state_hex_digs = 8
    state = [int(mac[k * state_hex_digs: (k + 1) * state_hex_digs], 16) for k in range(state_vars)]

    s = SHA1()
    key_filler = Message(b'\x00' * key_len)
    orig_msg_pad = s.formPad(len(msg) + key_len)
    new_msg = msg + orig_msg_pad + add_msg
    new_msg_pad = s.formPad(len(new_msg) + key_len)
    
    extended_mac = s.hash(add_msg + new_msg_pad, state, pad=False)
    return (new_msg, extended_mac)
    
