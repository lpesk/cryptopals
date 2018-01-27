from tools.message import Message
from tools.sha1 import SHA1
from tools.md4 import MD4
from tools.authentication import macSHA1, macMD4

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
    
